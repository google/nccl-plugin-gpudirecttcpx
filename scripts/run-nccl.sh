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

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

source "${SCRIPT_DIR}"/unix_client_prefix_selection.sh

run_nccl() {
  local -r benchmark=$1
  local -r ld_library_path_override=$2
  local -r gpu_per_node=$3
  local -r socket_ifnames=$4
  local -r data_b=$5
  local -r data_e=$6
  local nhosts=2
  if ! [[ -z "$7" ]]; then
    nhosts=$7
  fi

  for i in $(seq 1 1); do

  LD_LIBRARY_PATH=${ld_library_path_override} \
  mpirun --mca btl tcp,self --mca btl_tcp_if_include eth0 --allow-run-as-root \
    -np $(( gpu_per_node * "${nhosts}" )) \
    --hostfile "${SCRIPT_DIR}/hostfiles${nhosts}/hostfile${gpu_per_node}" \
    -x NCCL_SOCKET_IFNAME=eth0 \
    -x LD_LIBRARY_PATH -x PATH \
    -x NCCL_CROSS_NIC=0 \
    -x NCCL_ALGO=Ring \
    -x NCCL_PROTO=Simple \
    -x NCCL_NSOCKS_PERTHREAD=4 \
    -x NCCL_SOCKET_NTHREADS=1 \
    -x NCCL_MAX_NCHANNELS=8 \
    -x NCCL_MIN_NCHANNELS=8 \
    -x NCCL_DYNAMIC_CHUNK_SIZE=524288 \
    -x NCCL_BUFFSIZE=4194304 \
    -x CUDA_VISIBLE_DEVICES=0,1,2,3,4,5,6,7 \
    -x NCCL_GPUDIRECTTCPX_SOCKET_IFNAME="${socket_ifnames}" \
    -x NCCL_GPUDIRECTTCPX_CTRL_DEV=eth0 \
    -x NCCL_NET_GDR_LEVEL=PIX \
    -x NCCL_P2P_PXN_LEVEL=0 \
    -x NCCL_DEBUG=INFO -x NCCL_DEBUG_SUBSYS=ENV \
    -x NCCL_GPUDIRECTTCPX_UNIX_CLIENT_PREFIX="${UNIX_CLIENT_PREFIX}" \
    -x NCCL_GPUDIRECTTCPX_PROGRAM_FLOW_STEERING_WAIT_MICROS=1000000 \
    -x NCCL_GPUDIRECTTCPX_FORCE_ACK \
    /third_party/nccl-tests-mpi/build/"${benchmark}" \
      -b "${data_b}" -e "${data_e}" -f 2 -g 1 -w 5 --iters 20 2>&1 | \
    tee "a_${nhosts}_${gpu_per_node}_${socket_ifnames}_iter${i}.txt"
  done
}

run_nccl "$@"
