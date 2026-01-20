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

help() {
  echo "Usage: $ProgName <subcommand> [options]\n"
  echo "Subcommands:"
  echo "    install    Install NCCL plugin"
  echo "               --install-nccl installs NCCL main branch"
  echo "               --tune_net applies a tune network script"
  echo "               --nccl-plugin-buildtype installs a plugin build with"
  echo "                  selected options [release|debug|relwithdebinfo]"
  echo "    shell      Run interactive shell"
  echo "    daemon     Start sshd and sleep"
  echo "    debug-info Install a script grabbing debug info that can invoked"
  echo "               afterwards by"
  echo "               sudo /var/lib/tcpx/debug_info.sh"
}

install_subcommand() {

  mkdir -p /var/lib/tcpx/lib64

  local -r ARGUMENT_LIST=(
    "install-nccl"
    "tune_net"
    "nccl-plugin-buildtype:"
  )
  OPTS=$(getopt \
    --longoptions "$(printf "%s," "${ARGUMENT_LIST[@]}")" \
    --name "$(basename "$0")" \
    --options "" \
    -- "$@"
  )

  eval set -- "${OPTS}"

  local nccl_plugin_buildtype="release"
  local install_nccl_specified=false
  while (( $# )); do
    local flag="$1"; shift;
    case "${flag}" in
      --install-nccl)
        install_nccl_specified=true
      ;;
      --nccl-plugin-buildtype)
        nccl_plugin_buildtype="$1"; shift;
      ;;
      --tune_net)
        chmod 755 /scripts/tune_net.sh
        sudo mount -o remount,exec /home
        /scripts/tune_net.sh
      ;;
    esac
  done
  if $install_nccl_specified; then
    install_nccl
  fi
  install_nccl_plugin "${nccl_plugin_buildtype}"
}

install_nccl() {
  echo -n "Installing NCCL. "
  cp -P /third_party/nccl-netsupport/build/lib/libnccl.so* /var/lib/tcpx/lib64/
}

install_nccl_plugin() {
  local -r buildtype=$1
  echo -n "Installing NCCL plugin ${buildtype}, "

  local build_folder=""
  case "${buildtype}" in
    "release")
      echo "release"
      build_folder="nccl-plugin-gpudirecttcpx"
    ;;
    "debug")
      echo "debug"
      build_folder="nccl-plugin-gpudirecttcpx-debug"
    ;;
    "relwithdebinfo")
      echo "relwithdebinfo"
      build_folder="nccl-plugin-gpudirecttcpx-relwithdebinfo"
    ;;
    *)
      echo "unrecognized opt ${buildtype}"
    ;;
  esac

  cp "/${build_folder}/build/libnccl-net.so" /var/lib/tcpx/lib64/
}

gather_debug_info() {
  mkdir -p /var/lib/tcpx/
  cp /scripts/debug_info.sh /var/lib/tcpx/
}

SUBCOMMAND=$1
shift;

case ${SUBCOMMAND} in
  "install")
    echo "install"
    install_subcommand "$@"
    ;;
  "shell")
    echo "shell"
    service ssh restart
    /bin/bash
    ;;
  "daemon")
    echo "daemon"
    service ssh restart
    sleep inf
    ;;
  "debug-info")
    echo "debug-info"
    gather_debug_info
    ;;
  *)
    help
esac
