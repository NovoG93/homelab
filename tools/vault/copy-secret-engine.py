import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# CONFIGURATION
POD_NAME = 'vault-0'
NAMESPACE = 'vault'
VAULT_ADDR = 'http://127.0.0.1:8200'
VAULT_OPTIONS = 'VAULT_SKIP_VERIFY=true'
SOURCE_MOUNT = 'dev'
DEST_MOUNT = 'prod'


@dataclass(frozen=True)
class VaultCopyConfig:
    pod_name: str
    namespace: str
    vault_addr: str
    vault_skip_verify: bool
    source_mount: str
    dest_mount: str
    kv_version: int
    token_file_in_pod: str
    dry_run: bool
    verbose: bool


def _normalize_path(path: str) -> str:
    path = (path or '').strip()
    path = path.strip('/')
    return path


def _join_path(parent: str, child: str) -> str:
    parent = _normalize_path(parent)
    child = child.lstrip('/')
    if not parent:
        return _normalize_path(child)
    return _normalize_path(f"{parent}/{child}")


def _map_source_to_dest(
    full_source_path: str,
    source_mount: str,
    dest_mount: str,
) -> str:
    full_source_path = _normalize_path(full_source_path)
    source_mount = _normalize_path(source_mount)
    dest_mount = _normalize_path(dest_mount)

    # Replace only the leading mount segment.
    pattern = rf"^{re.escape(source_mount)}(?:(/)|$)"
    mapped = re.sub(
        pattern,
        lambda m: f"{dest_mount}{m.group(1) or ''}",
        full_source_path,
        count=1,
    )
    if mapped == full_source_path:
        raise ValueError(
            "Refusing to map path that does not start with source mount: "
            f"'{full_source_path}' (source mount: '{source_mount}')"
        )
    return mapped


def _kubectl_exec(
    args: List[str],
    *,
    namespace: str,
    pod_name: str,
    input_data: Optional[str] = None,
) -> Tuple[int, str, str]:
    cmd = ['kubectl', 'exec', '-n', namespace]
    if input_data is not None:
        cmd.append('-i')
    cmd += [pod_name, '--'] + args
    proc = subprocess.run(
        cmd,
        input=(input_data.encode('utf-8') if input_data is not None else None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return (
        proc.returncode,
        proc.stdout.decode('utf-8', errors='replace'),
        proc.stderr.decode('utf-8', errors='replace'),
    )


def _vault_exec(
    vault_args: List[str],
    *,
    cfg: VaultCopyConfig,
    token: str,
    input_data: Optional[str] = None,
    allow_nonzero: bool = False,
) -> Tuple[int, str, str]:
    env_args = [
        'env',
        f"VAULT_ADDR={cfg.vault_addr}",
        f"VAULT_TOKEN={token}",
    ]
    if cfg.vault_skip_verify:
        env_args.append('VAULT_SKIP_VERIFY=true')

    rc, out, err = _kubectl_exec(
        env_args + ['vault'] + vault_args,
        namespace=cfg.namespace,
        pod_name=cfg.pod_name,
        input_data=input_data,
    )
    if rc != 0 and not allow_nonzero:
        raise RuntimeError(
            "Vault command failed\n"
            f"  cmd: vault {' '.join(vault_args)}\n"
            f"  rc: {rc}\n"
            f"  stderr: {err.strip()}"
        )
    return rc, out, err


def get_vault_token():
    # Default: pulls root token from the same place as your bootstrap jobs.
    # Adjust via CLI with --token-file-in-pod.
    keys_location = '/tmp/keys/keys.json'
    cmd = [
        'sh',
        '-lc',
        (
            f"cat {keys_location} | grep 'Root Token' "
            "| awk -F: '{print $2}' | tr -d ' '"
        ),
    ]
    rc, out, err = _kubectl_exec(cmd, namespace=NAMESPACE, pod_name=POD_NAME)
    if rc != 0:
        raise RuntimeError(
            f"Failed to read Vault token from pod (rc={rc}): {err.strip()}"
        )
    token = out.strip()
    if not token:
        raise RuntimeError(
            'Vault token is empty; check /tmp/keys/keys.json inside the pod'
        )
    return token


def _get_token(cfg: VaultCopyConfig) -> str:
    env_token = os.environ.get('VAULT_TOKEN')
    if env_token:
        return env_token.strip()

    # Read token from a file inside the pod.
    rc, out, err = _kubectl_exec(
        ['cat', cfg.token_file_in_pod],
        namespace=cfg.namespace,
        pod_name=cfg.pod_name,
    )
    if rc == 0:
        token = out.strip()
        if token:
            return token

    # Fallback to your previous “keys.json” heuristic.
    return get_vault_token()


def _vault_kv_list(
    path: str, *, cfg: VaultCopyConfig, token: str
) -> List[str]:
    # 'vault kv list' exits non-zero if path is empty/missing.
    # Treat that as “no children”.
    rc, out, _err = _vault_exec(
        ['kv', 'list', '-format=json', path],
        cfg=cfg,
        token=token,
        allow_nonzero=True,
    )
    if rc != 0:
        return []
    try:
        items = json.loads(out)
    except json.JSONDecodeError:
        # Some Vault versions write warnings to stdout; consider that empty.
        return []
    if not isinstance(items, list):
        return []
    return [str(x) for x in items]


def _vault_kv_get_data(
    path: str, *, cfg: VaultCopyConfig, token: str
) -> Dict[str, Any]:
    _, out, _err = _vault_exec(
        ['kv', 'get', '-format=json', path],
        cfg=cfg,
        token=token,
    )
    payload = json.loads(out)

    if cfg.kv_version == 2:
        data = payload.get('data', {}).get('data', {})
    elif cfg.kv_version == 1:
        data = payload.get('data', {})
    else:
        raise ValueError(f"Unsupported kv version: {cfg.kv_version}")

    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected data shape for '{path}': {type(data)}")
    return data


def _vault_kv_put_data(
    path: str, data: Dict[str, Any], *, cfg: VaultCopyConfig, token: str
) -> None:
    # Some Vault CLI builds don't support '@-' for stdin.
    # Write the JSON to a temp file inside the pod and put from there.
    json_input = json.dumps(data)
    tmp_path = (
        f"/tmp/vault-kv-copy-{os.getpid()}-{int(time.time() * 1000)}.json"
    )
    try:
        rc, _out, err = _kubectl_exec(
            ['sh', '-lc', f"cat > {tmp_path}"],
            namespace=cfg.namespace,
            pod_name=cfg.pod_name,
            input_data=json_input,
        )
        if rc != 0:
            raise RuntimeError(
                f"Failed to write temp JSON in pod (rc={rc}): {err.strip()}"
            )

        _vault_exec(
            ['kv', 'put', path, f"@{tmp_path}"],
            cfg=cfg,
            token=token,
        )
    finally:
        _kubectl_exec(
            ['sh', '-lc', f"rm -f {tmp_path}"],
            namespace=cfg.namespace,
            pod_name=cfg.pod_name,
            input_data=None,
        )


def copy_secrets_recursive(*, cfg: VaultCopyConfig) -> None:
    token = _get_token(cfg)

    source_root = _normalize_path(cfg.source_mount)
    if not source_root:
        raise ValueError('source_mount must be non-empty')

    stack: List[str] = [source_root]
    visited: set[str] = set()

    while stack:
        current = _normalize_path(stack.pop())
        if not current or current in visited:
            continue
        visited.add(current)

        children = _vault_kv_list(current, cfg=cfg, token=token)
        if not children:
            # If list returns nothing, current might still be a leaf secret.
            # Try reading it; if it fails, just ignore.
            try:
                data = _vault_kv_get_data(current, cfg=cfg, token=token)
            except Exception:
                continue
            dest_path = _map_source_to_dest(
                current,
                cfg.source_mount,
                cfg.dest_mount,
            )
            print(f"Copying: {current} -> {dest_path}")
            if not cfg.dry_run:
                _vault_kv_put_data(dest_path, data, cfg=cfg, token=token)
            continue

        for child in children:
            if child.endswith('/'):
                stack.append(_join_path(current, child.rstrip('/')))
            else:
                full_source_path = _join_path(current, child)
                dest_path = _map_source_to_dest(
                    full_source_path,
                    cfg.source_mount,
                    cfg.dest_mount,
                )
                if cfg.verbose:
                    print(f"Copying: {full_source_path} -> {dest_path}")
                else:
                    print(f"Copying: {full_source_path}")

                if cfg.dry_run:
                    continue

                data = _vault_kv_get_data(
                    full_source_path,
                    cfg=cfg,
                    token=token,
                )
                _vault_kv_put_data(dest_path, data, cfg=cfg, token=token)


def _parse_args(argv: List[str]) -> VaultCopyConfig:
    p = argparse.ArgumentParser(
        description=(
            'Recursively copy Vault KV secrets from one mount to another '
            '(via kubectl exec).'
        )
    )
    p.add_argument(
        '--pod',
        default=POD_NAME,
        help='Vault pod name (default: vault-0)',
    )
    p.add_argument(
        '--namespace',
        default=NAMESPACE,
        help='Kubernetes namespace (default: vault)',
    )
    p.add_argument(
        '--vault-addr',
        default=VAULT_ADDR,
        help='Vault address inside the pod (default: http://127.0.0.1:8200)',
    )
    p.add_argument(
        '--skip-verify',
        action='store_true',
        default=('VAULT_SKIP_VERIFY=true' in VAULT_OPTIONS),
        help='Set VAULT_SKIP_VERIFY=true',
    )
    p.add_argument(
        '--source',
        default=SOURCE_MOUNT,
        help='Source KV mount (e.g. dev)',
    )
    p.add_argument(
        '--dest',
        default=DEST_MOUNT,
        help='Destination KV mount (e.g. prod)',
    )
    p.add_argument(
        '--kv-version',
        type=int,
        choices=[1, 2],
        default=2,
        help='KV engine version (default: 2)',
    )
    p.add_argument(
        '--token-file-in-pod',
        default='/tmp/keys/root-token',
        help=(
            'Path inside the pod containing a Vault token '
            '(fallback: /tmp/keys/keys.json parsing)'
        )
    )
    p.add_argument(
        '--dry-run',
        action='store_true',
        help='Print what would be copied without writing',
    )
    p.add_argument(
        '--verbose',
        action='store_true',
        help='Print full source->dest path mapping',
    )
    args = p.parse_args(argv)

    return VaultCopyConfig(
        pod_name=args.pod,
        namespace=args.namespace,
        vault_addr=args.vault_addr,
        vault_skip_verify=bool(args.skip_verify),
        source_mount=args.source,
        dest_mount=args.dest,
        kv_version=int(args.kv_version),
        token_file_in_pod=args.token_file_in_pod,
        dry_run=bool(args.dry_run),
        verbose=bool(args.verbose),
    )


def main(argv: Optional[List[str]] = None) -> int:
    try:
        cfg = _parse_args(argv or sys.argv[1:])
        print(
            f"Starting copy from '{cfg.source_mount}' to '{cfg.dest_mount}'..."
        )
        copy_secrets_recursive(cfg=cfg)
        print('Done!')
        return 0
    except KeyboardInterrupt:
        print('Interrupted', file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
