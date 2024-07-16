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

#ifndef NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_UNIX_SOCKET_CONNECTION_H_
#define NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_UNIX_SOCKET_CONNECTION_H_

#include "unix_socket_message.pb.h"
#include "unix_socket_proto.pb.h"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <atomic>
#include <functional>
#include <memory>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

#include <absl/status/status.h>

enum SendStatus {
  DONE = 0,
  IN_PROGRESS = 1,
  STOPPED = 2,
  ERROR = 3,
};

class UnixSocketConnection {
 public:
  explicit UnixSocketConnection(int fd);
  ~UnixSocketConnection();
  // return false if error occurs
  bool Receive();
  // return false if error occurs
  bool Send();
  bool HasNewMessageToRead() { return !incoming_.empty(); }
  bool HasPendingMessageToSend() { return !outgoing_.empty(); }
  void AddMessageToSend(UnixSocketMessage&& message) {
    outgoing_.emplace(std::move(message));
  }
  UnixSocketMessage ReadMessage();

 private:
  void SendProto(const UnixSocketProto& text, SendStatus* status);
  void SendFd(int fd, SendStatus* status);
  enum State {
    LENGTH = 0,
    PAYLOAD = 1,
  };
  int fd_{-1};
  State read_state_{LENGTH};
  uint16_t read_length_;
  size_t read_offset_{0};
  std::unique_ptr<char[]> read_buffer_;
  State send_state_{LENGTH};
  uint16_t send_length_;
  uint16_t send_length_network_order_;
  size_t send_offset_{0};
  char* send_buffer_;
  std::queue<UnixSocketMessage> incoming_;
  std::queue<UnixSocketMessage> outgoing_;
  std::string proto_data_;  // buffer for outgoing message on head
  struct msghdr send_msg_;
  struct iovec send_iov_;
  char send_control_[CMSG_SPACE(sizeof(int))];
  char send_dummy_byte_;
  struct msghdr recv_msg_;
  struct iovec recv_iov_;
  char recv_control_[CMSG_SPACE(sizeof(int))];
};

#endif // NET_GPUDIRECTTCPX_RXBUFMGRCLIENT_UNIX_SOCKET_CONNECTION_H_
