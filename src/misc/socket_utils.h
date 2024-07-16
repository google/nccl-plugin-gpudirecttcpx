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

#ifndef NET_GPUDIRECTTCPX_MISC_SOCKET_UTILS_H_
#define NET_GPUDIRECTTCPX_MISC_SOCKET_UTILS_H_

#include <arpa/inet.h>
#include <stdlib.h>

#include "adapter1.h"

/* Common socket address storage structure for IPv4/IPv6 */
union socketAddress {
  struct sockaddr sa;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
};

#define TCPX_SOCKET_SEND 0
#define TCPX_SOCKET_RECV 1

tcpxResult_t socketProgressOpt(int op, int fd, void *ptr, int size, int *offset,
                               int block);

tcpxResult_t socketProgress(int op, int fd, void *ptr, int size, int *offset);

tcpxResult_t socketProgress(int op, int fd, union socketAddress *addr,
                            void *ptr, int size, int *offset);

tcpxResult_t socketSpin(int op, int fd, void *ptr, int size, int *offset);

tcpxResult_t socketWait(int op, int fd, void *ptr, int size, int *offset);

tcpxResult_t socketWait(int op, int fd, union socketAddress *addr, void *ptr,
                        int size, int *offset);

tcpxResult_t socketSend(int fd, void *ptr, int size);

tcpxResult_t socketSend(int fd, union socketAddress *addr, void *ptr, int size);

tcpxResult_t socketRecv(int fd, void *ptr, int size, bool blocking = 1);

tcpxResult_t socketRecv(int fd, union socketAddress *addr, void *ptr, int size);

/* Format a string representation of a (struct sockaddr *) socket address using
 * getnameinfo()
 *
 * Output: "IPv4/IPv6 address<port>"
 */
const char* socketToString(const struct sockaddr* saddr, char* buf);
const char* socketToString(const union socketAddress* saddr, char* buf);
uint16_t socketToPort(struct sockaddr* saddr);

#define FLOW_STR_LEN 256
const char* fdToString(int fd, bool passive, char* buf, size_t len);

int findInterfaces(char* ifNames, union socketAddress* ifAddrs,
                          int ifNameMaxSize, int maxIfs);
int findInterfaces(const char* prefixList, char* names,
                          union socketAddress* addrs, int sock_family,
                          int maxIfNameSize, int maxIfs);

tcpxResult_t createListenSocket(int* fd, union socketAddress* localAddr,
                                       int port);

tcpxResult_t connectAddress(int* fd, union socketAddress* remoteAddr,
                                   union socketAddress* localAddr);
tcpxResult_t connectAddress(int* fd, union socketAddress* remoteAddr,
                                   union socketAddress* localAddr, int port);
tcpxResult_t connectAddress(int *fd, union socketAddress *remoteAddr,
                            union socketAddress *localAddr, int port,
                            bool match_local_port);

#include <string.h>
#include "debug1.h"
/* Allow the user to force the IPv4/IPv6 interface selection */
static inline int envSocketFamily(void) {
  int family = -1;  // Family selection is not forced, will use first one found
  char* env = TCPX_GET_ENV("SOCKET_FAMILY");
  if (env == NULL) return family;

  INFO(TCPX_ENV, "NET_GPUDIRECTTCPX_SOCKET_FAMILY set by environment to %s", env);

  if (strcmp(env, "AF_INET") == 0)
    family = AF_INET;  // IPv4
  else if (strcmp(env, "AF_INET6") == 0)
    family = AF_INET6;  // IPv6
  return family;
}


#endif  // NET_GPUDIRECTTCPX_MISC_SOCKET_UTILS_H_
