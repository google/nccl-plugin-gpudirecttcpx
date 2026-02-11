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

# Set Default CUDA Version Tag to 12.0
ARG DOCKER_BUILD_CUDA_VERSION=12.0

FROM nvidia/cuda:"${DOCKER_BUILD_CUDA_VERSION}".0-devel-ubuntu22.04 AS base

ARG DOCKER_BUILD_CUDA_VERSION
# Set Default NCCL Version Tag
ARG DOCKER_BUILD_NCCL_VERSION_TAG=v2.19.4-1

RUN echo "CUDA Version = $DOCKER_BUILD_CUDA_VERSION"
RUN echo "NCCL Version Tag = $DOCKER_BUILD_NCCL_VERSION_TAG"

ENV DEBIAN_FRONTEND='noninteractive'

RUN apt update && apt -y upgrade
RUN apt -y autoremove

RUN apt install -y --no-install-recommends \
    git openssh-server wget iproute2 vim libopenmpi-dev build-essential \
    cmake gdb python3 libmnl-dev \
    protobuf-compiler libprotobuf-dev rsync libssl-dev libcurl4-openssl-dev \
  && rm -rf /var/lib/apt/lists/*

ARG CUDA12_GENCODE='-gencode=arch=compute_90,code=sm_90'
ARG CUDA12_PTX='-gencode=arch=compute_90,code=compute_90'

WORKDIR /third_party
# Install NCCL
COPY build_temp/nccl-netsupport nccl-netsupport
WORKDIR nccl-netsupport
RUN make NVCC_GENCODE="$CUDA12_GENCODE $CUDA12_PTX" -j

WORKDIR /third_party
RUN git clone https://github.com/NVIDIA/nccl-tests.git
WORKDIR nccl-tests
RUN git fetch --all --tags
RUN make CUDA_HOME=/usr/local/cuda NCCL_HOME=/third_party/nccl-netsupport/build NVCC_GENCODE="$CUDA12_GENCODE $CUDA12_PTX" -j

WORKDIR /third_party
RUN git clone https://github.com/NVIDIA/nccl-tests.git nccl-tests-mpi
WORKDIR nccl-tests-mpi
RUN git fetch --all --tags
RUN make MPI=1 MPI_HOME=/usr/lib/x86_64-linux-gnu/openmpi CUDA_HOME=/usr/local/cuda NCCL_HOME=/third_party/nccl-netsupport/build NVCC_GENCODE="$CUDA12_GENCODE $CUDA12_PTX" -j

# install a newer version of cmake, which could find cuda automatically
WORKDIR /third_party
RUN wget https://github.com/Kitware/CMake/releases/download/v3.26.4/cmake-3.26.4.tar.gz
RUN tar zxf cmake-3.26.4.tar.gz
WORKDIR /third_party/cmake-3.26.4
RUN ./bootstrap --parallel=16 && make -j 16 && make install

# build googletest
WORKDIR /third_party
RUN git clone https://github.com/google/googletest.git -b v1.14.0
WORKDIR googletest
RUN mkdir build
WORKDIR build
RUN cmake -DCMAKE_CXX_STANDARD=17 -DCMAKE_POSITION_INDEPENDENT_CODE=ON .. && cmake --build . -j 8 --target all && cmake --install .

# build absl
WORKDIR /third_party
RUN git clone https://github.com/abseil/abseil-cpp.git
WORKDIR abseil-cpp
RUN git fetch --all --tags
RUN git checkout tags/20240116.2 -b build
WORKDIR build
RUN cmake -DCMAKE_CXX_STANDARD=17 -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DABSL_USE_GOOGLETEST_HEAD=ON .. && cmake --build . -j 8 --target all && cmake --install .

# build protobuf
WORKDIR /third_party
RUN git clone https://github.com/protocolbuffers/protobuf.git
WORKDIR protobuf
RUN git fetch --all --tags
RUN git checkout tags/v27.1 -b build
WORKDIR build
RUN cmake -DCMAKE_CXX_STANDARD=17 -DCMAKE_POSITION_INDEPENDENT_CODE=ON -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_ABSL_PROVIDER=package .. && cmake --build . -j 8 --target all && cmake --install .

# copy all license files
WORKDIR /third_party/licenses
RUN cp ../nccl-netsupport/LICENSE.txt license_nccl.txt
RUN cp ../nccl-tests/LICENSE.txt license_nccl_tests.txt
RUN cp ../abseil-cpp/LICENSE license_absl.txt
RUN cp ../protobuf/LICENSE license_protobuf.txt
RUN cp ../googletest/LICENSE license_gtest.txt

# Setup SSH to use port 222
RUN cd /etc/ssh/ && sed --in-place='.bak' 's/#Port 22/Port 222/' sshd_config && \
    sed --in-place='.bak' 's/#PermitRootLogin prohibit-password/PermitRootLogin prohibit-password/' sshd_config
RUN ssh-keygen -t rsa -b 4096 -q -f /root/.ssh/id_rsa -N "" -C ""
RUN touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
RUN cat /root/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys

# setup scripts directory
COPY scripts /scripts

# Copy NCCL plugin repo for multiple build flavors
COPY . /nccl-plugin-gpudirecttcpx/
COPY . /nccl-plugin-gpudirecttcpx-debug/
COPY . /nccl-plugin-gpudirecttcpx-relwithdebinfo/

# Indicate stripping source code post builds.
ARG REMOVE_SOURCE=1

# Install NCCL plugin "Release"
WORKDIR /nccl-plugin-gpudirecttcpx
RUN ./tcpx_cmake_build.sh $DOCKER_BUILD_NCCL_VERSION_TAG

# Install NCCL plugin "Debug"
WORKDIR /nccl-plugin-gpudirecttcpx-debug
RUN ./tcpx_cmake_build.sh $DOCKER_BUILD_NCCL_VERSION_TAG -DCMAKE_BUILD_TYPE=Debug

# Install NCCL plugin "Relwithdebinfo"
WORKDIR /nccl-plugin-gpudirecttcpx-relwithdebinfo
RUN ./tcpx_cmake_build.sh $DOCKER_BUILD_NCCL_VERSION_TAG -DCMAKE_BUILD_TYPE=RelWithDebInfo

FROM base AS use_standard

WORKDIR /
ENTRYPOINT ["/scripts/container_entry.sh"]
