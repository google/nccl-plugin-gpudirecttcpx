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

gpu_per_node=$1
SOCKET_IFNAMES=$2
DATA_B=$3
DATA_E=$4
NHOSTS=2
ITERS=$5

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

NCCL_PLUGIN_SO_DIR='/nccl-plugin-gpudirecttcpx/build'
# NCCL_PLUGIN_SO_DIR='/root/artzhu/'
# NCCL_PLUGIN_SO_DIR='/plugin/'

for i in $(seq 1 1); do

LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/third_party/nccl-netsupport/build/lib:${NCCL_PLUGIN_SO_DIR} \
mpirun --mca btl tcp,self --mca btl_tcp_if_include eth0 --allow-run-as-root \
  -np $(( gpu_per_node * "${NHOSTS}" )) \
  --hostfile "${SCRIPT_DIR}/hostfiles${NHOSTS}/hostfile${gpu_per_node}" \
  -x NCCL_SOCKET_IFNAME=eth0 \
  -x LD_LIBRARY_PATH -x PATH \
  -x NCCL_CROSS_NIC=0 \
  -x NCCL_ALGO=Ring \
  -x NCCL_PROTO=Simple \
  -x NCCL_NSOCKS_PERTHREAD=4 \
  -x NCCL_SOCKET_NTHREADS=1 \
  -x NCCL_MAX_NCHANNELS=16 \
  -x NCCL_MIN_NCHANNELS=16 \
  -x NCCL_DYNAMIC_CHUNK_SIZE=524288 \
  -x NCCL_BUFFSIZE=4194304 \
  -x CUDA_VISIBLE_DEVICES=0,1,2,3,4,5,6,7 \
  -x NCCL_GPUDIRECTTCPX_SOCKET_IFNAME="${SOCKET_IFNAMES}" \
  -x NCCL_GPUDIRECTTCPX_CTRL_DEV=eth0 \
  -x NCCL_NET_GDR_LEVEL=PIX \
  -x NCCL_P2P_PXN_LEVEL=0 \
  -x NCCL_GPUDIRECTTCPX_TX_BINDINGS="dcn1:8-19;dcn2:8-19;dcn3:60-73;dcn4:60-73" \
  -x NCCL_GPUDIRECTTCPX_RX_BINDINGS="dcn1:20-31;dcn2:20-31;dcn3:74-87;dcn4:74-87" \
  -x NCCL_DEBUG=INFO -x NCCL_DEBUG_SUBSYS=INIT,ENV,GRAPH,NET \
  -x NCCL_GPUDIRECTTCPX_PROGRAM_FLOW_STEERING_WAIT_MICROS=1000000 \
  -x NCCL_P2P_NET_CHUNKSIZE=524288 \
  -x NCCL_P2P_PCI_CHUNKSIZE=524288 \
  -x NCCL_P2P_NVL_CHUNKSIZE=1048576 \
  -x NCCL_GPUDIRECTTCPX_FORCE_ACK \
  taskset -c 0-7,104-111,52-59,156-163 /third_party/nccl-tests-pipeline/build/sendrecv_perf \
    -b "${DATA_B}" -e "${DATA_E}" -f 2 -g 1 -w 5 --iters "${ITERS}" 2>&1 | \
  tee "a_${NHOSTS}_${gpu_per_node}_${SOCKET_IFNAMES}_iter${i}.txt"
done
