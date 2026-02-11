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

DO_PUSH="false"
DRY_RUN="false"
CLEAN="false"
REPO_PATH=""
IMAGE_NAME=""
IMAGE_TAG=""
GETOPTS="hdpcv:u:r:i:t:"
DOCKER_CMD_IMG_NAME_TAG=""
NCCL_VERSION_TAG="${NCCL_VERSION_TAG:-v2.19.4-1}"
CUDA_VERSION="${CUDA_VERSION:-12.0}"
LEGACY_IMAGE_NAME=""
LEGACY_IMAGE_TAG=""

usage() {
  echo "Usage: $0 [-h] [-d] [-p] [-c] [-v <nccl_version_tag>] [-u <cuda_version>] "
  echo "          [-r <repo_path>] [-i <image_name>] [-t <image_tag>]"
  echo "          [-I <legacy_image_name>] [-T <legacy_image_tag>]\n"
  echo "Where:"
  echo "  -h        : Display this help message."
  echo "  -p        : Push docker image to a specified repository."
  echo "  -d        : Dry run only."
  echo "  -c        : Clean build sources."
  echo "  -v        : NCCL version tag (default - v2.19.4-1)"
  echo "  -u        : CUDA version (default - 12.0)"
  echo "  -r        : Repository path to push the image to."
  echo "  -i        : Image name for the current build."
  echo "  -t        : Image tag for the current build."
}

while getopts ${GETOPTS} opt; do
  case "${opt}" in
    h)
      usage
      exit 0
      ;;
    d)
      DRY_RUN="true"
      ;;
    p)
      DO_PUSH="true"
      ;;
    c)
      CLEAN="true"
      ;;
    v)
      NCCL_VERSION_TAG="${OPTARG}"
      ;;
    u)
      CUDA_VERSION="${OPTARG}"
      ;;
    r)
      REPO_PATH="${OPTARG}"
      ;;
    i)
      IMAGE_NAME="${OPTARG}"
      ;;
    t)
      IMAGE_TAG="${OPTARG}"
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
shift $((OPTIND - 1))


# If push is specified, repo name, image name and tag are provided.
# If push not specified - image name and tag are provided.
if [[ "${DO_PUSH}" == "true" ]]; then
  if [[ -z "${REPO_PATH}" ]]; then
    echo "Repository path (-r) is required when push (-p) is set."
    usage
    exit 1
  fi
  if [[ -z "${IMAGE_NAME}" ]]; then
    echo "Image name (-i) is required when push (-p) is set."
    usage
    exit 1
  fi
  if [[ -z "${IMAGE_TAG}" ]]; then
    echo "Image tag (-t) is required when push (-p) is set."
    usage
    exit 1
  fi
  DOCKER_CMD_IMG_NAME_TAG="${REPO_PATH}/${IMAGE_NAME}:${IMAGE_TAG}"
else
  if [[ -z "${IMAGE_NAME}" ]]; then
    echo "Image name (-i) is required."
    usage
    exit 1
  fi
  if [[ -z "${IMAGE_TAG}" ]]; then
    echo "Image tag (-t) is required."
    usage
    exit 1
  fi
  DOCKER_CMD_IMG_NAME_TAG="${IMAGE_NAME}:${IMAGE_TAG}"
fi

# Dry Run
if [[ "${DRY_RUN}" == "true"  ]]; then
  exit 0
fi

# Prepare required sources in local directory
./prepare_source.sh -p -v "${NCCL_VERSION_TAG}"

docker build --provenance=false --sbom=false --build-arg DOCKER_BUILD_NCCL_VERSION_TAG="${NCCL_VERSION_TAG}" --build-arg DOCKER_BUILD_CUDA_VERSION="${CUDA_VERSION}" -f Dockerfile . -t "${DOCKER_CMD_IMG_NAME_TAG}" --target use_standard

# Push the Docker Image
if [[ "${DO_PUSH}" == "true" ]]; then
  docker push "${DOCKER_CMD_IMG_NAME_TAG}"
fi

if [[ "${CLEAN}" == "true"  ]]; then
  ./prepare_source.sh -c
  echo "Directory is clean."
fi
