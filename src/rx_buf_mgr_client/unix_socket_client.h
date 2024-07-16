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

#ifndef NET_GPUDIRECTTCPX_SOCK_UNIX_SOCKET_CLIENT_H_
#define NET_GPUDIRECTTCPX_SOCK_UNIX_SOCKET_CLIENT_H_

#include "unix_socket_connection.h"

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include <queue>
#include <string>
#include <vector>
#include <absl/status/status.h>
#include <absl/status/statusor.h>

class UnixSocketClient {
 public:
  explicit UnixSocketClient(std::string path) : path_(path) {}
  absl::Status Connect();
  absl::StatusOr<UnixSocketMessage> Receive();
  void Send(UnixSocketMessage msg);
  bool IsConnected (){
    return conn_ != NULL;
  }

 private:
  std::unique_ptr<UnixSocketConnection> conn_;
  std::string path_;
};

absl::Status ConnectAndSendMessage(UnixSocketMessage message,
                                   UnixSocketMessage* response,
                                   UnixSocketClient* client);

#endif // NET_GPUDIRECTTCPX_SOCK_UNIX_SOCKET_CLIENT_H_
