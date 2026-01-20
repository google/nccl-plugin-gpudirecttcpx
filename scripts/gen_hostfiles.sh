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

len() {
  local -r arr=($@)
  echo "${#arr[@]}"
}

NRANKS_FACTORS=(1 2 4 8)

NHOSTS=$(len "$@")
echo "generating hostfiles for ${NHOSTS} hosts: "
for h in "$@"; do echo "$h"; done

mkdir -p "hostfiles${NHOSTS}"

for nr in "${NRANKS_FACTORS[@]}";
do
  rm -f "hostfiles${NHOSTS}/hostfile${nr}"
  touch "hostfiles${NHOSTS}/hostfile${nr}"
  for h in "$@";
  do
    echo "$h port=222 slots=${nr}" >> "hostfiles${NHOSTS}/hostfile${nr}"
  done
done
