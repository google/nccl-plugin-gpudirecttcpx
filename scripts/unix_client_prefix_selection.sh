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

# preference order
PREFERENCE_ORDER=(
  "/run/tcpx"
  "/tmp"
)

UNIX_CLIENT_PREFIX="/tmp" # backwards compatibility default

for possible_dir in "${PREFERENCE_ORDER[@]}"; do
  if [[ -e "${possible_dir}/rx_rule_manager" ]]; then
    UNIX_CLIENT_PREFIX="${possible_dir}"
  fi
done

echo UNIX_CLIENT_PREFIX "${UNIX_CLIENT_PREFIX}"
