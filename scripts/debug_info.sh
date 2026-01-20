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

date
hostname

#
# Setup
#

NVIDIA_SMI_BIN=""

case ${SCRIPT_ENV:-""} in
  "gke")
    NVIDIA_SMI_BIN="/home/kubernetes/bin/nvidia/bin/nvidia-smi"
    ;;
  *)
    NVIDIA_SMI_BIN="/var/lib/nvidia/bin/nvidia-smi"
    ;;
esac

#
# Versions
#

version_COS() {
  cat /etc/os-release
}

version_CUDA() {
  ${NVIDIA_SMI_BIN}
}

for dep in "COS" "CUDA"; do
  echo "${dep}: "; version_${dep}
done

#
# Versions
#

settings_mtu() {
  ip link list | egrep "eth[0-9]+"
}

settings_ip_route() {
  ip route show
}

settings_sys_kernel_core_pattern() {
  cat /proc/sys/kernel/core_pattern
}

for setting in "mtu"  "sys_kernel_core_pattern" "ip_route"; do
  echo "${setting}: "; settings_${setting} || echo
done

#
# Tunings
#

vm_net_tunings=(
  "/proc/sys/net/ipv4/tcp_mtu_probing"
  "/proc/sys/net/ipv4/tcp_slow_start_after_idle"
  "/proc/sys/net/ipv4/tcp_no_metrics_save"
  "/proc/sys/net/ipv4/tcp_rmem"
  "/proc/sys/net/ipv4/tcp_wmem"
  "/proc/sys/net/core/optmem_max"
  "/proc/sys/net/core/somaxconn"
  "/proc/sys/net/ipv4/tcp_max_syn_backlog"
)

for vnt in "${vm_net_tunings[@]}"; do
  echo -n "${vnt}: "; cat "${vnt}" || echo
done

#
# Longer Logs
#

log_dmesg() {
  sudo dmesg
}

log_ecc() {
  ${NVIDIA_SMI_BIN} --query-gpu=ecc.errors.uncorrected.volatile.total --format=csv
  ${NVIDIA_SMI_BIN} --query-gpu=ecc.errors.uncorrected.aggregate.total --format=csv
}

for target in "dmesg"  "ecc"; do
  echo "${target}: "; log_${target}
done

