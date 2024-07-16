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

#include "unix_socket_connection.h"


#include <arpa/inet.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <chrono>
#include <iostream>
#include <string>
#include <utility>

#include <absl/status/status.h>
#include <absl/strings/str_format.h>


UnixSocketConnection::UnixSocketConnection(int fd) : fd_(fd) {
  read_length_ = sizeof(uint16_t);
  read_buffer_.reset(new char[read_length_]);
}

UnixSocketConnection::~UnixSocketConnection() {
  if (fd_ >= 0) {
    close(fd_);
  }
}

bool UnixSocketConnection::Receive() {
  memset(&recv_msg_, 0, sizeof(recv_msg_));

  // Setup IO vector
  recv_iov_.iov_base = read_buffer_.get() + read_offset_;
  recv_iov_.iov_len = read_length_ - read_offset_;
  recv_msg_.msg_iov = &recv_iov_;
  recv_msg_.msg_iovlen = 1;
  recv_msg_.msg_control = &recv_control_;
  recv_msg_.msg_controllen = sizeof(recv_control_);

  int bytes_read = recvmsg(fd_, &recv_msg_, 0);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&recv_msg_);

  if (cmsg != nullptr && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
      cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
    int fd = *((int*)CMSG_DATA(cmsg));
    UnixSocketMessage message;
    message.set_fd(fd);
    incoming_.emplace(std::move(message));
    return true;
  }

  if (bytes_read < 0) return false;
  if (bytes_read == 0) return true;

  read_offset_ += bytes_read;

  if (read_offset_ == read_length_) {
    switch (read_state_) {
      case LENGTH: {
        read_length_ = ntohs(*((uint16_t*)read_buffer_.get()));
        read_state_ = PAYLOAD;
        break;
      }
      case PAYLOAD: {
        std::string payload;
        payload.reserve(read_length_);
        for (int i = 0; i < read_length_; ++i) {
          payload.push_back(read_buffer_[i]);
        }
        UnixSocketMessage message;
        UnixSocketProto* proto = message.mutable_proto();
        proto->ParseFromString(payload);
        incoming_.emplace(std::move(message));
        read_length_ = sizeof(uint16_t);
        read_state_ = LENGTH;
        break;
      }
      default:
        assert(false && "bad read_state_");
    }
    read_buffer_.reset(new char[read_length_]);
    read_offset_ = 0;
  }
  return true;
}

void UnixSocketConnection::SendFd(int fd, SendStatus* status) {
  memset(&send_msg_, 0, sizeof(send_msg_));
  send_msg_.msg_control = &send_control_;
  send_msg_.msg_controllen = sizeof(send_control_);

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&send_msg_);
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  *((int*)CMSG_DATA(cmsg)) = fd;

  send_iov_.iov_base = &send_dummy_byte_;
  send_iov_.iov_len = sizeof(send_dummy_byte_);
  send_msg_.msg_iov = &send_iov_;
  send_msg_.msg_iovlen = 1;

  if (sendmsg(fd_, &send_msg_, 0) < 0) {
    *status = ERROR;
  }
  *status = DONE;
}

void UnixSocketConnection::SendProto(const UnixSocketProto& proto,
                                    SendStatus* status) {
  memset(&send_msg_, 0, sizeof(send_msg_));
  proto_data_.clear();
  proto.SerializeToString(&proto_data_);
  if (send_state_ == LENGTH && send_offset_ == 0) {
    send_length_ = sizeof(uint16_t);
    send_length_network_order_ = htons((uint16_t)proto_data_.size());
    send_buffer_ = (char*)&send_length_network_order_;
  }
  // Setup IO vector
  send_iov_.iov_base = send_buffer_ + send_offset_;
  send_iov_.iov_len = send_length_ - send_offset_;
  send_msg_.msg_iov = &send_iov_;
  send_msg_.msg_iovlen = 1;

  int bytes_sent = sendmsg(fd_, &send_msg_, 0);

  if (bytes_sent < 0) {
    *status = ERROR;
    return;
  }
  send_offset_ += bytes_sent;
  if (send_offset_ != send_length_) {
    // Send operation is not finished, break the loop here and wait for the
    // next chance.
    *status = STOPPED;
    return;
  }
  // Send operation completes.  Move forward to next state or next message.
  switch (send_state_) {
    case LENGTH: {
      send_length_ = (uint16_t)proto_data_.size();
      send_buffer_ = (char*)proto_data_.data();
      send_state_ = PAYLOAD;
      *status = IN_PROGRESS;
      break;
    }
    case PAYLOAD: {
      send_length_ = sizeof(uint16_t);
      send_buffer_ = (char*)&send_length_network_order_;
      send_state_ = LENGTH;
      *status = DONE;
      break;
    }
    default:
      assert(false && "bad send_state_");
  }
  send_offset_ = 0;
}

bool UnixSocketConnection::Send() {
  while (!outgoing_.empty()) {
    UnixSocketMessage& outmsg = outgoing_.front();

    SendStatus status = ERROR;

    if (outmsg.has_fd()) {
      SendFd(outmsg.fd(), &status);
    } else if (outmsg.has_proto()) {
      SendProto(outmsg.proto(), &status);
    }

    if (status == ERROR) {
      return false;
    } else if (status == DONE) {
      outgoing_.pop();
    } else if (status == STOPPED) {
      return true;
    }
  }
  return true;
}

UnixSocketMessage UnixSocketConnection::ReadMessage() {
  if (incoming_.empty()) {
    return {};
  }
  UnixSocketMessage ret = std::move(incoming_.front());
  incoming_.pop();
  return ret;
}
