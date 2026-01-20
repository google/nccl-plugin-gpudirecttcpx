/*
 Copyright 2026 Google LLC

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

#ifndef NET_GPUDIRECTTCPX_NETDEV_BRIDGE_H_
#define NET_GPUDIRECTTCPX_NETDEV_BRIDGE_H_

#include <libmnl/libmnl.h>
#include <stdint.h>

// Class object for Netlink Socket to facilitate Netlink APIs for bind-tx.
class NetdevBridge {
 public:
  explicit NetdevBridge() {
    nl_ = nullptr;
    familyId_ = -1;
    seq_ = 0;
    isInited_ = false;
    dmaBufId_ = -1;
  }

  ~NetdevBridge() {
    destroyNetdevBridge();
  }

  // Rule of Five
  NetdevBridge(const NetdevBridge&) = delete;
  NetdevBridge& operator=(const NetdevBridge&) = delete;
  NetdevBridge(NetdevBridge&&) = delete;
  NetdevBridge& operator=(NetdevBridge&&) = delete;

  int initNetdevBridge();
  void destroyNetdevBridge();
  int bindTx(uint32_t ifindex, uint32_t dmabuf_fd);
  bool isInited() const { return isInited_; }
  int getDmaBufId() const { return  dmaBufId_; }

 private:
  struct mnl_socket* nl_;
  int familyId_;
  unsigned int seq_;
  bool isInited_;
  int dmaBufId_;
};

#endif
