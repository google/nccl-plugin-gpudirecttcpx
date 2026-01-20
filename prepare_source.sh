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

PREPARE="false"
CLEAN="false"
GETOPTS="hpv:c"
NCCL_VERSION_TAG="${NCCL_VERSION_TAG:-v2.25.1-1}"

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
BUILD_WORKDIR="${SCRIPT_DIR}/build_temp"

usage() {
  echo "Usage: $0 [-h] [-p] [-v <nccl version tag>] [-c] \n"
  echo "Where:"
  echo "  -h        : Display this help message."
  echo "  -p        : Prepare sources for build."
  echo "  -v        : NCCL version tag (default v2.25.1-1)."
  echo "  -c        : Clean build sources."
}

prepare() {

  # Check if source already exists. If so, bail.
  if [ -d "${BUILD_WORKDIR}" ]; then
    exit 0
  fi

  # Create a temporary directory to clone NCCL into.
  mkdir -p "$BUILD_WORKDIR"
  cd "$BUILD_WORKDIR"

  # Clone Nvidia NCCL
  git clone https://github.com/NVIDIA/nccl.git nccl-netsupport
  cd nccl-netsupport
  git fetch --all --tags

  # NCCL Version Tag Checkout
  git checkout "${NCCL_VERSION_TAG}"

  cd "$SCRIPT_DIR"
}

clean() {
  cd "$SCRIPT_DIR"
  rm -rf ${BUILD_WORKDIR}
}

while getopts ${GETOPTS} opt; do
  case "${opt}" in
    h)
      usage
      exit 0
      ;;
    p)
      PREPARE="true"
      ;;
    v)
      NCCL_VERSION_TAG="${OPTARG}"
      ;;
    c)
      CLEAN="true"
      ;;
    :)
      echo "Option -${OPTARG} requires an argument." >&2
      usage
      ;;
    \?)
      echo "Invalid option: -${OPTARG}" >&2
      usage
      ;;
  esac
done
shift "$((OPTIND-1))"

if [[ "${PREPARE}" == "true" && "${CLEAN}" == "true" ]]; then
  echo "Cannot set prepare and clean together."
  exit 1
fi

if [[ "${PREPARE}" == "true" ]]; then
  prepare
fi

if [[ "${CLEAN}" == "true" ]]; then
  clean
fi
