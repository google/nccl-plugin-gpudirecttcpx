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

#include <unistd.h>

#include <string>

#include <absl/status/status.h>
#include <absl/strings/str_format.h>

#include "application_registry_client.h"

ApplicationRegistryClient::ApplicationRegistryClient(std::string prefix) : prefix_(prefix) {}

absl::Status ApplicationRegistryClient::Init() {
  const std::string server_addr = "rxdm_application_registry";

  client_ = std::make_unique<UnixSocketClient>(
      absl::StrFormat("%s/%s", prefix_, server_addr));

  UnixSocketMessage message;
  UnixSocketProto* proto = message.mutable_proto();
  ApplicationRegisterRequest* arr = proto->mutable_application_register_request();
  arr->set_register_client(true);

  UnixSocketMessage response;
  long pid = getpid();
  if (auto status = ConnectAndSendMessage(message, &response, client_.get());
      !status.ok()) {
    return absl::InternalError(
        absl::StrFormat("register pid %ld failed connect and send: %s", pid,
                        status.ToString()));
  }

  return absl::OkStatus();
}

ApplicationRegistryClient::~ApplicationRegistryClient() {
  (void) Cleanup();
}

absl::Status ApplicationRegistryClient::Cleanup() {
  const std::string server_addr = "rxdm_application_registry";

  UnixSocketMessage message;
  UnixSocketProto* proto = message.mutable_proto();
  ApplicationRegisterRequest* arr = proto->mutable_application_register_request();
  arr->set_register_client(false);

  UnixSocketMessage response;
  if (auto status = ConnectAndSendMessage(message, &response, client_.get());
      !status.ok()) {
    long pid = getpid();
    return absl::InternalError(
        absl::StrFormat("deregister pid %ld failed connect and send: %s", pid,
                        status.ToString()));
  }

  return absl::OkStatus();
}
