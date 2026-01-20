#!/bin/bash

# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -o pipefail

# Strip the version tag. For eg. strip from v2.25.1-1 to 2.25.1
# to be used in cmake.
VERSION_TAG_ARG=$1
STRIPPED_NCCL_VERSION=$(echo "${VERSION_TAG_ARG}" | sed 's/^v//;s/-[^-]*$//')
echo "Stripped NCCL version ${STRIPPED_NCCL_VERSION}"

# Remove the first argument (the version tag) from the positional parameters
# since we pass the rest of the arg list to cmake.
shift

# Delete any previous cmake build instances
rm -rf build

# Build TCPX Plugin. Specify NCCL Version here.
cmake -S . -B build -DNCCL_PATH=/third_party/nccl-netsupport/ \
        -DNET_GPUDIRECTTCPX_EXPORT=nccl -DNCCL_VERSION=${STRIPPED_NCCL_VERSION} "$@"

cmake --build build

# Strip sources and only leave out libnccl-net.so
if [[ -v REMOVE_SOURCE ]] && (( ${REMOVE_SOURCE} != 0 )); then
  rm -rf src/ tests/ build/src build/CMakeFiles .git build_temp/ scripts/
  for fname in $(find . -type f -name "*" ! -name "libnccl-net.so"); do
    rm "${fname}"
  done
fi
