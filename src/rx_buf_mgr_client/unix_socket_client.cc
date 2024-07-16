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

#include "unix_socket_client.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <sys/un.h>
#include <unistd.h>
#include <memory>
#include <vector>
#include <absl/strings/str_format.h>

absl::Status UnixSocketClient::Connect() {
  if (path_.empty())
    return absl::InvalidArgumentError("unix client missing file path to domain socket.");

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);

  if (fd < 0) {
    int error_number = errno;
    return absl::ErrnoToStatus(
        errno, absl::StrFormat("unix client socket() error: %d", error_number));
  }

  struct sockaddr_un server_addr;
  int server_addr_len;
  server_addr.sun_family = AF_UNIX;
  strcpy(server_addr.sun_path, path_.c_str());
  server_addr_len =
      strlen(server_addr.sun_path) + sizeof(server_addr.sun_family);
  if (connect(fd, (struct sockaddr*)&server_addr, server_addr_len) < 0) {
    int error_number = errno;
    return absl::ErrnoToStatus(
        errno, absl::StrFormat("unix client connect() error: %d", error_number));
  }
  conn_ = std::make_unique<UnixSocketConnection>(fd);
  return absl::OkStatus();
}

absl::StatusOr<UnixSocketMessage> UnixSocketClient::Receive() {
  while (!conn_->HasNewMessageToRead()) {
    if (!conn_->Receive()) {
      int error_number = errno;
      return absl::ErrnoToStatus(
          errno, absl::StrFormat("unix client receive() error: %d", error_number));
    }
  }
  return conn_->ReadMessage();
}

void UnixSocketClient::Send(UnixSocketMessage msg) {
  conn_->AddMessageToSend(std::move(msg));
  while (conn_->HasPendingMessageToSend()) {
    if (!conn_->Send()) {
      break;
    }
  }
}

absl::Status ConnectAndSendMessage(UnixSocketMessage message,
                                   UnixSocketMessage* response,
                                   UnixSocketClient* client) {
  if (!client->IsConnected()) {
    auto status = client->Connect();
    if (!status.ok()) return status;
  }

  client->Send(message);

  auto response_status = client->Receive();

  if (!response_status.ok()) return response_status.status();

  *response = response_status.value();

  return absl::OkStatus();
}
