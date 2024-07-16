/*
 Copyright 2024 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include "rx_pool.h"

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug1.h"
#include "flags.h"
#include "unix_socket_client.h"
#include "cuda_checks.h"

CUdeviceptr gpumem_import(char* gpu_pci_addr) {
  // std::string nvdmad_path = absl::StrFormat("/tmp/nvdma-%s", gpu_pci_addr);
  char nvdmad_path[128];
  sprintf(nvdmad_path, "/tmp/nvdma-%s", gpu_pci_addr);
  CUipcMemHandle mem_handle;
  CUdeviceptr ptr;
  int fd, ret;

  fd = open(nvdmad_path, O_RDONLY);
  if (fd == -1) {
    INFO(TCPX_NET, "skip %s", nvdmad_path);
    return 0;
    // error(1, errno, "open %s", nvdmad_path.c_str());
  }

  ret = read(fd, &mem_handle, sizeof(mem_handle));
  if (ret == -1) error(1, errno, "read %s", nvdmad_path);
  if (ret != sizeof(mem_handle))
    error(1, 0, "read %s: %dB", nvdmad_path, ret);
  if (close(fd)) error(1, errno, "close %s", nvdmad_path);

  CUASSERT(
      cuIpcOpenMemHandle(&ptr, mem_handle, cudaIpcMemLazyEnablePeerAccess));
  return ptr;
}

struct IpcGpuMemFdMetadata {
  int fd{-1};
  size_t size{0};
  size_t align{0};
};
CuIpcMemfdHandle* GpumemImport(const CUcontext ctx, const char* gpu_pci_addr, const char* ipc_prefix) {
  char client_id[128];
  IpcGpuMemFdMetadata gpumem_fd_metadata;

  // fetch ipc shareable fd
  snprintf(client_id, 128, "%s/get_gpu_fd_%s", ipc_prefix, gpu_pci_addr);
  UnixSocketClient gpumem_fd_by_gpu_pci_client(client_id);
  absl::Status status = gpumem_fd_by_gpu_pci_client.Connect();
  if (!status.ok()) {
    WARN("unix client %s, gpumem fd client connect failed %s", client_id, std::string(status.message()).c_str());
    return nullptr;
  }
  UnixSocketMessage req;
  UnixSocketProto* req_mutable_proto = req.mutable_proto();
  req_mutable_proto->set_raw_bytes(gpu_pci_addr);
  gpumem_fd_by_gpu_pci_client.Send(req);
  absl::StatusOr<UnixSocketMessage> resp =
      gpumem_fd_by_gpu_pci_client.Receive();
  if (!resp.status().ok()) {
    WARN("unix client %s, recv fd failed %s", client_id, std::string(resp.status().message()).c_str());
    return nullptr;
  }
  if (!resp.value().has_fd() || resp.value().fd() < 0) {
    WARN("unix client %s, GPU fd not found %s", client_id, gpu_pci_addr);
    return nullptr;
  }

  // fetch gpu memory metadata
  snprintf(client_id, 128, "%s/get_gpu_metadata_%s", ipc_prefix, gpu_pci_addr);
  UnixSocketClient gpumem_metadata_by_gpu_pci_client(client_id);
  absl::Status status1 = gpumem_metadata_by_gpu_pci_client.Connect();
  if (!status1.ok()) {
    WARN("unix client %s, gpumem metadata client connect failed %s", client_id, std::string(status1.message()).c_str());
    return nullptr;
  }
  UnixSocketMessage req_metadata;
  UnixSocketProto* md_mutable_proto = req_metadata.mutable_proto();
  md_mutable_proto->set_raw_bytes(gpu_pci_addr);
  gpumem_metadata_by_gpu_pci_client.Send(req_metadata);
  absl::StatusOr<UnixSocketMessage> resp_metadata =
      gpumem_metadata_by_gpu_pci_client.Receive();
  if (!resp_metadata.status().ok()) {
    WARN("unix client %s, recv metadata failed %s", client_id, std::string(resp_metadata.status().message()).c_str());
    return nullptr;
  }
  if (!resp_metadata.value().has_proto() ||
      !resp_metadata.value().proto().has_raw_bytes()) {
    WARN("unix client %s, GPU metadata not found %s", client_id, gpu_pci_addr);
    return nullptr;
  } else {
    memcpy((void*)&gpumem_fd_metadata,
           (void*)resp_metadata.value().proto().raw_bytes().data(),
           resp_metadata.value().proto().raw_bytes().size());
  }
  int dev_id;
  CUDAASSERT(cudaDeviceGetByPCIBusId(&dev_id, gpu_pci_addr));
  return new CuIpcMemfdHandle(ctx, resp.value().fd(), dev_id,
                              gpumem_fd_metadata.size,
                              gpumem_fd_metadata.align);
}
CuIpcMemfdHandle* GpumemImport(const CUcontext ctx, const char* gpu_pci_addr) {
  return GpumemImport(ctx, gpu_pci_addr, kUnixClientPrefix);
}
