#!/bin/bash

set -eou pipefail
BASE_DIR="$(git rev-parse --show-toplevel)"


bash ${BASE_DIR}/kind/hack/lifecycle.bash startup "$@"