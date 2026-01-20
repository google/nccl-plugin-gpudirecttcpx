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

#include "tx_pool.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>

#include "common.h"
#include "debug1.h"
#include "param1.h"
#include "tx_pool.h"
#include "../macro.h"
#include "../netdev/netdev_bridge.h"


/**** p2pdma begin ****/

const char cfg_procfs_prefix[] = "/proc/driver/nvdma";

struct page_vec_create_info {
  unsigned long gpu_vaddr;
  unsigned long size;
};

#define PAGE_VEC_CREATE _IOW('c', 'c', struct page_vec_create_info)
#define PAGE_VEC_START_OFF _IOR('c', 'o', int)

int get_gpumem_pages_fd(char pci_addr[16], CUdeviceptr gpu_mem,
                         size_t gpu_mem_sz, int* align_offp) {
  char path[256];
  sprintf(path, "%s/%s/new_fd", cfg_procfs_prefix, pci_addr);

  int ret;
  int fd = open(path, O_WRONLY);
  if (fd == -1) {
    WARN("Error opening %s", path);
    return -EBADF;
  }

  struct page_vec_create_info create_info = {(unsigned long) gpu_mem, gpu_mem_sz};
  ret = ioctl(fd, PAGE_VEC_CREATE, &create_info);
  if (ret < 0) {
    WARN("ioctl() failed: %s", strerror(errno));
    goto err_close;
  }

  if (close(fd)) {
    WARN("close: %s", strerror(errno));
    return -EIO;
  }

  INFO(TCPX_NET, "Registered region 0x%lx of %lu Bytes", gpu_mem, gpu_mem_sz);
  if (ioctl(ret, PAGE_VEC_START_OFF, align_offp)) {
    WARN("Error getting start offset: %s", strerror(errno));
  }
  return ret;

err_close:
  close(fd);
  return -EIO;
}

/**** p2pdma end ****/

/**** dmabuf begin ****/

#include "linux/types.h"

// internal ioctl API structs
const char cfg_nvp2pdmabuf_procfs_prefix[] = "/proc/driver/nvp2p_dma_buf";
struct gpumem_dma_buf_create_info {
  unsigned long gpu_vaddr;
  unsigned long size;
};
#define GPUMEM_DMA_BUF_CREATE _IOW('c', 'c', struct gpumem_dma_buf_create_info)

struct dma_buf_create_pages_info {
  __u64 pci_bdf[3];
  __s32 dma_buf_fd;
  __s32 create_page_pool;
};

#define DMA_BUF_BASE 'b'
#define DMA_BUF_CREATE_PAGES _IOW(DMA_BUF_BASE, 2, struct dma_buf_create_pages_info)
TCPX_PARAM(RegDmabufUseInternalApi, "GPUDIRECTTCPX_REG_DMABUF_USE_INTERNAL_API", 0);

// Returns dma_buf_id for upstream implementation (failure on internal
// implementation).
static int bind_tx_nl(NetdevBridge *netdev_bridge, char* nic_pci_addr, uint32_t dmabuf_fd) {
  int error = 0;
  int pci_addr_len = strlen(nic_pci_addr);
  uint32_t ifindex = 0;

  // Hardcoded conversion of PCI Address to ifname. Use if_nametoindex()
  // to get ifindex for given ifname.
  if (strncmp(nic_pci_addr, "0000:06:00.0", pci_addr_len) == 0) {
    ifindex = if_nametoindex("eth1");
  }

  if (strncmp(nic_pci_addr, "0000:0c:00.0", pci_addr_len) == 0) {
    ifindex = if_nametoindex("eth2");
  }

  if (strncmp(nic_pci_addr, "0000:86:00.0", pci_addr_len) == 0) {
    ifindex = if_nametoindex("eth3");
  }

  if (strncmp(nic_pci_addr, "0000:8c:00.0", pci_addr_len) == 0) {
    ifindex = if_nametoindex("eth4");
  }

  error = netdev_bridge->bindTx(ifindex, dmabuf_fd);
  if (error < 0) {
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : Bind TX using Netlink Failed.");
    goto done;
  }

  // If Netlink API is successful, error will have the return dmabuf id.
  INFO(TCPX_INIT | TCPX_NET,
       "NET/" PRODUCT_NAME " : Bind TX using Netlink Succeeded."
       " DMA BUF ID: %d", error);

done:
  return error;
}

// Returns gpu memory binding fd (gpu_mem_fd) on internal implementation
// (not called on upstream implementation).
static int bind_tx_ioctl(char* nic_pci_addr, uint32_t dmabuf_fd) {
  int error = 0;
  struct dma_buf_create_pages_info info = {0};
  uint16_t pci_bdf[3] = {0};

  info.dma_buf_fd = dmabuf_fd;
  info.create_page_pool = 0;

  error = sscanf(nic_pci_addr, "0000:%hx:%hx.%hx", &pci_bdf[0], &pci_bdf[1],
                 &pci_bdf[2]);
  if (error != 3) {
    error = -EINVAL;
    goto done;
  }

  info.pci_bdf[0] = pci_bdf[0];
  info.pci_bdf[1] = pci_bdf[1];
  info.pci_bdf[2] = pci_bdf[2];

  error = ioctl(dmabuf_fd, DMA_BUF_CREATE_PAGES, &info);
  if (error < 0) {
    perror("ioctl get dma_buf frags");
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : Bind TX using ioctl() Failed.");
    error = -EIO;
    goto done;
  }

  // If ioctl() call is successful, error will have the return gpu mem fd.
  INFO(TCPX_INIT | TCPX_NET,
       "NET/" PRODUCT_NAME " : Bind TX using ioctl() Succeeded."
       " GPU MEM FD: %d", error);
done:
  return error;
}

// This function returns the gpu_mem_fd for internal implementation or
// dma_buf_id for upstream implementation.
int get_gpumem_dmabuf_pages_fd(NetdevBridge *netdev_bridge, char* gpu_pci_addr,
                               char* nic_pci_addr, CUdeviceptr gpu_mem,
                               size_t gpu_mem_sz, int* dma_buf_fd) {
  int err, ret, fd;

  if (TCPX_GET_PARAM(RegDmabufUseInternalApi) == 0) {
    CUresult cu_ret;
    cu_ret = cuMemGetHandleForAddressRange((void*)dma_buf_fd, (CUdeviceptr)gpu_mem,
                                  gpu_mem_sz, CU_MEM_RANGE_HANDLE_TYPE_DMA_BUF_FD,
                                  0);

    if (*dma_buf_fd < 0) {
      const char* name, *msg;
      cuGetErrorName(cu_ret, &name);
      cuGetErrorString(cu_ret, &msg);
      WARN("cuMemGetHandleForAddressRange (%p, %zu) failed, %s %s", gpu_mem, gpu_mem_sz, name, msg);
      return -1;
    }
  } else
  {
    char path[256];
    sprintf(path, "%s/%s/new_fd", cfg_nvp2pdmabuf_procfs_prefix, gpu_pci_addr);

    fd = open(path, O_WRONLY);
    if (fd == -1) {
      WARN("Error opening %s", path);
      return -EBADF;
    }

    INFO(TCPX_NET, "create_info = { %p, %zu }", gpu_mem, gpu_mem_sz);
    struct gpumem_dma_buf_create_info create_info = {gpu_mem, gpu_mem_sz};
    ret = ioctl(fd, GPUMEM_DMA_BUF_CREATE, &create_info);
    if (ret < 0) {
      perror("ioctl gpumem dma_buf create");
      err = -EIO;
      goto err_close;
    }

    if (close(fd)) {
      perror("close");
      err = -EIO;
      return err;
    }

    *dma_buf_fd = ret;
  }

  INFO(TCPX_INIT | TCPX_NET,
       "NET/" PRODUCT_NAME ": Registered dmabuf region 0x%lx of %lu Bytes", gpu_mem,
       gpu_mem_sz);

  // First use Netlink based API for BIND-TX
  if (netdev_bridge->isInited()) {
    ret = bind_tx_nl(netdev_bridge, nic_pci_addr, *dma_buf_fd);
    if (ret) {
      // Successful Netlink Bind.
      goto done;
    }
  } else {
      INFO(TCPX_INIT | TCPX_NET,
           "NET/" PRODUCT_NAME " : Skipping Bind TX using Netlink"
           " since Netlink Init Failed. Falling back to ioctl().");
  }

  // Fallback to IOCTL based API for BIND-TX
  ret = bind_tx_ioctl(nic_pci_addr, *dma_buf_fd);
  if (ret < 0) {
    err = ret;
    WARN("NET/" PRODUCT_NAME " : Bind TX failed for both Netlink and ioctl().");
    goto err_close_dmabuf;
  }

done:
  return ret;

err_close_dmabuf:
  close(*dma_buf_fd);
  return err;
err_close:
  close(fd);
  return err;
}

/**** dmabuf end ****/
