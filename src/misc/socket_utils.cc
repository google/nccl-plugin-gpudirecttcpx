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

#include "socket_utils.h"

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../macro.h"
#include "adapter1.h"
#include "checks1.h"

const char *fdToString(int fd, bool passive, char *buf, size_t len);

tcpxResult_t socketProgressOpt(int op, int fd, void *ptr, int size, int *offset,
                               int block) {
  int bytes = 0;
  do {
    if (op == TCPX_SOCKET_RECV) {
      bytes = recv(fd, (char *)ptr + (*offset), size - (*offset),
                   block ? 0 : MSG_DONTWAIT);
    }
    if (op == TCPX_SOCKET_SEND) {
      bytes = send(fd, (char *)ptr + (*offset), size - (*offset),
                   block ? 0 : MSG_DONTWAIT);
    }
    if (op == TCPX_SOCKET_RECV && bytes == 0) {
      char buf[FLOW_STR_LEN];
      WARN("Net/" PRODUCT_NAME " : Connection closed by remote peer, %s",
           fdToString(fd, /*passive=*/true, buf, FLOW_STR_LEN));
      return tcpxSystemError;
    }
    if (bytes == -1) {
      if (errno != EINTR && errno != EWOULDBLOCK && errno != EAGAIN) {
        char buf[FLOW_STR_LEN];
        WARN("Call to %s failed, %s : %s",
             op == TCPX_SOCKET_SEND ? "send" : "recv",
             fdToString(fd, op == TCPX_SOCKET_RECV, buf, FLOW_STR_LEN),
             strerror(errno));
        return tcpxSystemError;
      } else {
        bytes = 0;
      }
    }
    (*offset) += bytes;
  } while (bytes > 0 && (*offset) < size);
  return tcpxSuccess;
}

tcpxResult_t socketProgress(int op, int fd, void *ptr, int size, int *offset) {
  return socketProgressOpt(op, fd, ptr, size, offset, 0);
}

tcpxResult_t socketProgress(int op, int fd, union socketAddress *addr,
                            void *ptr, int size, int *offset) {
  return socketProgress(op, fd, ptr, size, offset);
}

tcpxResult_t socketSpin(int op, int fd, void *ptr, int size, int *offset) {
  while (*offset < size)
    TCPXCHECK(socketProgressOpt(op, fd, ptr, size, offset, 0));
  return tcpxSuccess;
}

tcpxResult_t socketWait(int op, int fd, void *ptr, int size, int *offset) {
  while (*offset < size)
    TCPXCHECK(socketProgressOpt(op, fd, ptr, size, offset, 1));
  return tcpxSuccess;
}

tcpxResult_t socketWait(int op, int fd, union socketAddress *addr, void *ptr,
                        int size, int *offset) {
  return socketWait(op, fd, ptr, size, offset);
}

tcpxResult_t socketSend(int fd, void *ptr, int size) {
  int offset = 0;
  TCPXCHECK(socketWait(TCPX_SOCKET_SEND, fd, ptr, size, &offset));
  return tcpxSuccess;
}

tcpxResult_t socketSend(int fd, union socketAddress *addr, void *ptr,
                        int size) {
  return socketSend(fd, ptr, size);
}

tcpxResult_t socketRecv(int fd, void *ptr, int size, bool blocking) {
  int offset = 0;
  TCPXCHECK(socketProgress(TCPX_SOCKET_RECV, fd, ptr, size, &offset));
  if (offset == size) return tcpxSuccess;
  if (offset == 0 && !blocking) return tcpxInProgress;
  TCPXCHECK(socketWait(TCPX_SOCKET_RECV, fd, ptr, size, &offset));
  return tcpxSuccess;
}

tcpxResult_t socketRecv(int fd, union socketAddress *addr, void *ptr,
                        int size) {
  return socketRecv(fd, ptr, size);
}

/********************************************************************************/

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <linux/tcp.h>

#define SLEEP_INT 1000  // connection retry sleep interval in usec
#define RETRY_REFUSED_TIMES 2e4  // connection refused retry times before reporting a timeout (20 sec)
#define RETRY_TIMEDOUT_TIMES 3  // connection timed out retry times (each one can take 20s)
#define SOCKET_NAME_MAXLEN (NI_MAXHOST + NI_MAXSERV)

struct netIf {
  char prefix[64];
  int port;
};

int parseStringList(const char* string, struct netIf* ifList,
                           int maxList) {
  if (!string) return 0;

  const char* ptr = string;

  int ifNum = 0;
  int ifC = 0;
  char c;
  do {
    c = *ptr;
    if (c == ':') {
      if (ifC > 0) {
        ifList[ifNum].prefix[ifC] = '\0';
        ifList[ifNum].port = atoi(ptr + 1);
        ifNum++;
        ifC = 0;
      }
      while (c != ',' && c != '\0') c = *(++ptr);
    } else if (c == ',' || c == '\0') {
      if (ifC > 0) {
        ifList[ifNum].prefix[ifC] = '\0';
        ifList[ifNum].port = -1;
        ifNum++;
        ifC = 0;
      }
    } else {
      ifList[ifNum].prefix[ifC] = c;
      ifC++;
    }
    ptr++;
  } while (ifNum < maxList && c);
  return ifNum;
}

bool matchIf(const char* string, const char* ref, bool matchExact) {
  // Make sure to include '\0' in the exact case
  int matchLen = matchExact ? strlen(string) + 1 : strlen(ref);
  return strncmp(string, ref, matchLen) == 0;
}

bool matchPort(const int port1, const int port2) {
  if (port1 == -1) return true;
  if (port2 == -1) return true;
  if (port1 == port2) return true;
  return false;
}

bool matchIfList(const char* string, int port, struct netIf* ifList,
                        int listSize, bool matchExact) {
  // Make an exception for the case where no user list is defined
  if (listSize == 0) return true;

  for (int i = 0; i < listSize; i++) {
    if (matchIf(string, ifList[i].prefix, matchExact) &&
        matchPort(port, ifList[i].port)) {
      return true;
    }
  }
  return false;
}

/* Format a string representation of a (struct sockaddr *) socket address using
 * getnameinfo()
 *
 * Output: "IPv4/IPv6 address<port>"
 */
const char* socketToString(const struct sockaddr* saddr, char* buf) {
  if (buf == NULL || saddr == NULL) return NULL;
  if (saddr->sa_family != AF_INET && saddr->sa_family != AF_INET6) {
    buf[0] = '\0';
    return buf;
  }
  char host[NI_MAXHOST], service[NI_MAXSERV];
  (void)getnameinfo(saddr, sizeof(union socketAddress), host, NI_MAXHOST,
                    service, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
  sprintf(buf, "%s<%s>", host, service);
  return buf;
}

const char* socketToString(const union socketAddress* saddr, char* buf) {
  return socketToString(&saddr->sa, buf);
}

const char* fdToString(int fd, bool passive, char* buf, size_t len) {
  struct sockaddr sock_addr;
  socklen_t sock_len = sizeof(sock_addr);
  if (getsockname(fd, (struct sockaddr*)&sock_addr, &sock_len) != 0) {
    WARN("getsockname %s", strerror(errno));
  }
  struct sockaddr peer_addr;
  socklen_t peer_len = sizeof(peer_addr);
  if (getpeername(fd, (struct sockaddr*)&peer_addr, &peer_len) != 0) {
    WARN("getpeername %s", strerror(errno));
  }

  char sock_buf[NI_MAXHOST + NI_MAXSERV + 2];
  char peer_buf[NI_MAXHOST + NI_MAXSERV + 2];
  socketToString(&sock_addr, sock_buf);
  socketToString(&peer_addr, peer_buf);

  snprintf(buf, len, "%s%s%s %s", sock_buf, (passive ? "<-" : "->"), peer_buf, (passive ? "rx" : "tx"));
  return buf;
}


inline uint16_t socketToPort(struct sockaddr* saddr) {
  return ntohs(saddr->sa_family == AF_INET
                   ? ((struct sockaddr_in*)saddr)->sin_port
                   : ((struct sockaddr_in6*)saddr)->sin6_port);
}

int findInterfaces(const char* prefixList, char* names,
                          union socketAddress* addrs, int sock_family,
                          int maxIfNameSize, int maxIfs) {
  char line[SOCKET_NAME_MAXLEN + 1];
  struct netIf userIfs[MAX_IFS];
  bool searchNot = prefixList && prefixList[0] == '^';
  if (searchNot) prefixList++;
  bool searchExact = prefixList && prefixList[0] == '=';
  if (searchExact) prefixList++;
  int nUserIfs = parseStringList(prefixList, userIfs, MAX_IFS);

  int found = 0;
  struct ifaddrs *interfaces, *interface;
  getifaddrs(&interfaces);
  for (interface = interfaces; interface && found < maxIfs;
       interface = interface->ifa_next) {
    if (interface->ifa_addr == NULL) continue;

    /* We only support IPv4 & IPv6 */
    int family = interface->ifa_addr->sa_family;
    if (family != AF_INET && family != AF_INET6) continue;

    INFO(TCPX_INIT | TCPX_NET, "Found interface %s:%s", interface->ifa_name,
          socketToString(interface->ifa_addr, line));

    /* Allow the caller to force the socket family type */
    if (sock_family != -1 && family != sock_family) continue;

    /* We also need to skip IPv6 loopback interfaces */
    if (family == AF_INET6) {
      struct sockaddr_in6* sa = (struct sockaddr_in6*)(interface->ifa_addr);
      if (IN6_IS_ADDR_LOOPBACK(&sa->sin6_addr)) continue;
    }

    // check against user specified interfaces
    if (!(matchIfList(interface->ifa_name, -1, userIfs, nUserIfs, searchExact) ^
          searchNot)) {
      continue;
    }

    // Check that this interface has not already been saved
    // getifaddrs() normal order appears to be; IPv4, IPv6 Global, IPv6 Link
    bool duplicate = false;
    for (int i = 0; i < found; i++) {
      if (strcmp(interface->ifa_name, names + i * maxIfNameSize) == 0) {
        duplicate = true;
        break;
      }
    }

    if (!duplicate) {
      // Store the interface name
      strncpy(names + found * maxIfNameSize, interface->ifa_name,
              maxIfNameSize);
      // Store the IP address
      int salen =
          (family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
      memcpy(addrs + found, interface->ifa_addr, salen);
      found++;
    }
  }

  freeifaddrs(interfaces);
  return found;
}

bool matchSubnet(struct ifaddrs local_if, union socketAddress* remote) {
  /* Check family first */
  int family = local_if.ifa_addr->sa_family;
  if (family != remote->sa.sa_family) {
    return false;
  }

  if (family == AF_INET) {
    struct sockaddr_in* local_addr = (struct sockaddr_in*)(local_if.ifa_addr);
    struct sockaddr_in* mask = (struct sockaddr_in*)(local_if.ifa_netmask);
    struct sockaddr_in& remote_addr = remote->sin;
    struct in_addr local_subnet, remote_subnet;
    local_subnet.s_addr = local_addr->sin_addr.s_addr & mask->sin_addr.s_addr;
    remote_subnet.s_addr = remote_addr.sin_addr.s_addr & mask->sin_addr.s_addr;
    return (local_subnet.s_addr ^ remote_subnet.s_addr) ? false : true;
  } else if (family == AF_INET6) {
    struct sockaddr_in6* local_addr = (struct sockaddr_in6*)(local_if.ifa_addr);
    struct sockaddr_in6* mask = (struct sockaddr_in6*)(local_if.ifa_netmask);
    struct sockaddr_in6& remote_addr = remote->sin6;
    struct in6_addr& local_in6 = local_addr->sin6_addr;
    struct in6_addr& mask_in6 = mask->sin6_addr;
    struct in6_addr& remote_in6 = remote_addr.sin6_addr;
    bool same = true;
    int len = 16;                    // IPv6 address is 16 unsigned char
    for (int c = 0; c < len; c++) {  // Network byte order is big-endian
      char c1 = local_in6.s6_addr[c] & mask_in6.s6_addr[c];
      char c2 = remote_in6.s6_addr[c] & mask_in6.s6_addr[c];
      if (c1 ^ c2) {
        same = false;
        break;
      }
    }
    // At last, we need to compare scope id
    // Two Link-type addresses can have the same subnet address even though they
    // are not in the same scope For Global type, this field is 0, so a
    // comparison wouldn't matter
    same &= (local_addr->sin6_scope_id == remote_addr.sin6_scope_id);
    return same;
  } else {
    WARN("Net : Unsupported address family type");
    return false;
  }
}

int findInterfaceMatchSubnet(char* ifNames,
                                    union socketAddress* localAddrs,
                                    union socketAddress* remoteAddr,
                                    int ifNameMaxSize, int maxIfs) {
  char line[SOCKET_NAME_MAXLEN + 1];
  char line_a[SOCKET_NAME_MAXLEN + 1];
  int found = 0;
  struct ifaddrs *interfaces, *interface;
  getifaddrs(&interfaces);
  for (interface = interfaces; interface && !found;
       interface = interface->ifa_next) {
    if (interface->ifa_addr == NULL) continue;

    /* We only support IPv4 & IPv6 */
    int family = interface->ifa_addr->sa_family;
    if (family != AF_INET && family != AF_INET6) continue;

    // check against user specified interfaces
    if (!matchSubnet(*interface, remoteAddr)) {
      continue;
    }

    // Store the local IP address
    int salen =
        (family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    memcpy(localAddrs + found, interface->ifa_addr, salen);

    // Store the interface name
    strncpy(ifNames + found * ifNameMaxSize, interface->ifa_name,
            ifNameMaxSize);

    INFO(TCPX_INIT | TCPX_NET,
          "NET : Found interface %s:%s in the same subnet as remote address %s",
          interface->ifa_name, socketToString(&(localAddrs[found].sa), line),
          socketToString(&(remoteAddr->sa), line_a));
    found++;
    if (found == maxIfs) break;
  }

  if (found == 0) {
    WARN("Net : No interface found in the same subnet as remote address %s",
         socketToString(&(remoteAddr->sa), line_a));
  }
  freeifaddrs(interfaces);
  return found;
}

tcpxResult_t GetSocketAddrFromString(union socketAddress* ua,
                                            const char* ip_port_pair) {
  if (!(ip_port_pair && strlen(ip_port_pair) > 1)) {
    WARN("Net : string is null");
    return tcpxInvalidArgument;
  }

  bool ipv6 = ip_port_pair[0] == '[';
  /* Construct the sockaddress structure */
  if (!ipv6) {
    struct netIf ni;
    // parse <ip_or_hostname>:<port> string, expect one pair
    if (parseStringList(ip_port_pair, &ni, 1) != 1) {
      WARN("Net : No valid <IPv4_or_hostname>:<port> pair found");
      return tcpxInvalidArgument;
    }

    struct addrinfo hints, *p;
    int rv;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(ni.prefix, NULL, &hints, &p)) != 0) {
      WARN("Net : error encountered when getting address info : %s",
           gai_strerror(rv));
      return tcpxInvalidArgument;
    }

    // use the first
    if (p->ai_family == AF_INET) {
      struct sockaddr_in& sin = ua->sin;
      memcpy(&sin, p->ai_addr, sizeof(struct sockaddr_in));
      sin.sin_family = AF_INET;  // IPv4
      // inet_pton(AF_INET, ni.prefix, &(sin.sin_addr));  // IP address
      sin.sin_port = htons(ni.port);  // port
    } else if (p->ai_family == AF_INET6) {
      struct sockaddr_in6& sin6 = ua->sin6;
      memcpy(&sin6, p->ai_addr, sizeof(struct sockaddr_in6));
      sin6.sin6_family = AF_INET6;      // IPv6
      sin6.sin6_port = htons(ni.port);  // port
      sin6.sin6_flowinfo = 0;           // needed by IPv6, but possibly obsolete
      sin6.sin6_scope_id = 0;           // should be global scope, set to 0
    } else {
      WARN("Net : unsupported IP family");
      return tcpxInvalidArgument;
    }

    freeaddrinfo(p);  // all done with this structure

  } else {
    int i, j = -1, len = strlen(ip_port_pair);
    for (i = 1; i < len; i++) {
      if (ip_port_pair[i] == '%') j = i;
      if (ip_port_pair[i] == ']') break;
    }
    if (i == len) {
      WARN("Net : No valid [IPv6]:port pair found");
      return tcpxInvalidArgument;
    }
    bool global_scope =
        (j == -1
             ? true
             : false);  // If no % found, global scope; otherwise, link scope

    char ip_str[NI_MAXHOST], port_str[NI_MAXSERV], if_name[IFNAMSIZ];
    memset(ip_str, '\0', sizeof(ip_str));
    memset(port_str, '\0', sizeof(port_str));
    memset(if_name, '\0', sizeof(if_name));
    strncpy(ip_str, ip_port_pair + 1, global_scope ? i - 1 : j - 1);
    strncpy(port_str, ip_port_pair + i + 2, len - i - 1);
    int port = atoi(port_str);
    if (!global_scope)
      strncpy(if_name, ip_port_pair + j + 1,
              i - j - 1);  // If not global scope, we need the intf name

    struct sockaddr_in6& sin6 = ua->sin6;
    sin6.sin6_family = AF_INET6;                     // IPv6
    inet_pton(AF_INET6, ip_str, &(sin6.sin6_addr));  // IP address
    sin6.sin6_port = htons(port);                    // port
    sin6.sin6_flowinfo = 0;  // needed by IPv6, but possibly obsolete
    sin6.sin6_scope_id =
        global_scope
            ? 0
            : if_nametoindex(
                  if_name);  // 0 if global scope; intf index if link scope
  }
  return tcpxSuccess;
}

int sortInterfaces(char* ifNames, union socketAddress* ifAddrs, int nIfs, int ifNameMaxSize) {
  char *_ifName = (char*) malloc(ifNameMaxSize);
  if (!_ifName) { perror("malloc"); return -1; }

  union socketAddress _ifAddr;
  bool done = false;
  while (!done) {
    done = true;
    for (int i = 0; i < nIfs - 1; i++) {
      char *s1 = ifNames + i * ifNameMaxSize;
      char *s2 = ifNames + (i + 1) * ifNameMaxSize;
      union socketAddress *a1 = ifAddrs + i;
      union socketAddress *a2 = ifAddrs + i + 1;
      if (strncmp(s1, s2, ifNameMaxSize) > 0) {
        done = false;
        memcpy(_ifName, s1, ifNameMaxSize);
        memcpy(&_ifAddr, a1, sizeof(union socketAddress));

        memcpy(s1, s2, ifNameMaxSize);
        memcpy(a1, a2, sizeof(union socketAddress));

        memcpy(s2, _ifName, ifNameMaxSize);
        memcpy(a2, &_ifAddr, sizeof(union socketAddress));
      }
    }
  }
  free(_ifName);

  return nIfs;
}

int findInterfaces(char* ifNames, union socketAddress* ifAddrs,
                          int ifNameMaxSize, int maxIfs) {
  static int shownIfName = 0;
  int nIfs = 0;
  // Allow user to force the INET socket family selection
  int sock_family = envSocketFamily();
  // User specified interface
  char* env = TCPX_GET_ENV("SOCKET_IFNAME");
  if (env && strlen(env) > 1) {
    INFO(TCPX_ENV, "NET_GPUDIRECTTCPX_SOCKET_IFNAME set by environment to %s", env);
    // Specified by user : find or fail
    if (shownIfName++ == 0) INFO(TCPX_NET, "NET_GPUDIRECTTCPX_SOCKET_IFNAME set to %s", env);
    nIfs = findInterfaces(env, ifNames, ifAddrs, sock_family, ifNameMaxSize,
                          maxIfs);
  } else {
    // Try to automatically pick the right one
    // Start with IB
    nIfs = findInterfaces("ib", ifNames, ifAddrs, sock_family, ifNameMaxSize,
                          maxIfs);
    // else see if we can get some hint from COMM ID
    if (nIfs == 0) {
      char* commId = getenv("NET_COMM_ID");
      if (commId && strlen(commId) > 1) {
        INFO(TCPX_ENV, "NET_COMM_ID set by environment to %s", commId);
        // Try to find interface that is in the same subnet as the IP in comm id
        union socketAddress idAddr;
        GetSocketAddrFromString(&idAddr, commId);
        nIfs = findInterfaceMatchSubnet(ifNames, ifAddrs, &idAddr,
                                        ifNameMaxSize, maxIfs);
      }
    }
    // Then look for anything else (but not docker or lo)
    if (nIfs == 0)
      nIfs = findInterfaces("^docker,lo", ifNames, ifAddrs, sock_family,
                            ifNameMaxSize, maxIfs);
    // Finally look for docker, then lo.
    if (nIfs == 0)
      nIfs = findInterfaces("docker", ifNames, ifAddrs, sock_family,
                            ifNameMaxSize, maxIfs);
    if (nIfs == 0)
      nIfs = findInterfaces("lo", ifNames, ifAddrs, sock_family, ifNameMaxSize,
                            maxIfs);
  }

  nIfs = sortInterfaces(ifNames, ifAddrs, nIfs, ifNameMaxSize);
  if (nIfs < 0) WARN("sortInterfaces failed");

  return nIfs;
}

tcpxResult_t createListenSocket(int* fd, union socketAddress* localAddr,
                                       int port) {
  /* IPv4/IPv6 support */
  int family = localAddr->sa.sa_family;
  int salen = (family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

  /* Create socket and bind it to a port */
  int sockfd = socket(family, SOCK_STREAM, 0);
  if (sockfd == -1) {
    WARN("Net : Socket creation failed : %s", strerror(errno));
    return tcpxSystemError;
  }

  if (socketToPort(&localAddr->sa)) {
    // Port is forced by env. Make sure we get the port.
    int opt = 1;
    SYSCHECK(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                        sizeof(opt)),
             "setsockopt");
  }

  // INFO(TCPX_INIT | TCPX_NET, "setting sin/sin6 port to %d", port);
  if (localAddr->sa.sa_family == AF_INET) {
    localAddr->sin.sin_port = htons(port);
  } else {
    localAddr->sin6.sin6_port = htons(port);
  }

  SYSCHECK(bind(sockfd, &localAddr->sa, salen), "bind");

  /* Get the assigned Port */
  socklen_t size = salen;
  SYSCHECK(getsockname(sockfd, &localAddr->sa, &size), "getsockname");

  /* Put the socket in listen mode
   * NB: The backlog will be silently truncated to the value in
   * /proc/sys/net/core/somaxconn
   */
  SYSCHECK(listen(sockfd, 16384), "listen");
  *fd = sockfd;
  return tcpxSuccess;
}

tcpxResult_t assignPort(union socketAddress *addr, int port) {
  int family = addr->sa.sa_family;
  if (family != AF_INET && family != AF_INET6) {
    WARN("Error : connecting to address with family %d is neither AF_INET(%d) "
         "nor AF_INET6(%d)",
         family, AF_INET, AF_INET6);
    return tcpxInternalError;
  }
  if (port > 0) {
    if (family == AF_INET) {
      addr->sin.sin_port = htons(port);
    } else {
      addr->sin6.sin6_port = htons(port);
    }
  }
  return tcpxSuccess;
}

tcpxResult_t connectAddressInternal(int* fd, union socketAddress* remoteAddr,
                                   union socketAddress* localAddr, int port, bool match_local_port) {
  char buf0[1024];
  char buf1[1024];
  // INFO(tcpx_NET, "connectAddress(fd, %s, %s, %d)",
  //      socketToString(remoteAddr, buf0), socketToString(localAddr, buf1), port);

  union socketAddress rAddr, lAddr;
  memcpy(&rAddr, remoteAddr, sizeof rAddr);
  memcpy(&lAddr, localAddr, sizeof lAddr);
  /* IPv4/IPv6 support */
  assignPort(&rAddr, port);
  if (match_local_port) {
    TCPXCHECK(assignPort(&lAddr, port));
  }

  INFO(TCPX_NET, "connectAddress(fd, %s, %s, %d)",
       socketToString(&rAddr, buf0), socketToString(&lAddr, buf1), port);

  int family = rAddr.sa.sa_family;
  int salen = (family == AF_INET) ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);

  /* Connect to a hostname / port */
  *fd = socket(family, SOCK_STREAM, 0);
  if (*fd == -1) {
    WARN("Net : Socket creation failed : %s", strerror(errno));
    return tcpxSystemError;
  }
  int lSalen = (lAddr.sa.sa_family == AF_INET) ? sizeof(sockaddr_in)
                                               : sizeof(sockaddr_in6);
  if (bind(*fd, &(lAddr.sa), lSalen)) {
    WARN("Net : Socket bind failed : %s", strerror(errno));
    return tcpxInternalError;
  }

  const int one = 1;
  SYSCHECK(setsockopt(*fd, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(int)),
           "setsockopt");

  char line[SOCKET_NAME_MAXLEN + 1];
  INFO(TCPX_INIT | TCPX_NET, "Connecting to socket %s",
       socketToString(&rAddr.sa, line));

  int ret;
  int timedout_retries = 0;
  int refused_retries = 0;
retry:
  SYSCHECKSYNC(connect(*fd, &rAddr.sa, salen), "connect", ret);
  if (ret == 0) return tcpxSuccess;
  if ((errno == ECONNREFUSED || errno == ETIMEDOUT)) {
    if ((errno == ECONNREFUSED && ++refused_retries < RETRY_REFUSED_TIMES) ||
        (errno == ETIMEDOUT && ++timedout_retries < RETRY_TIMEDOUT_TIMES)) {
      if (refused_retries % 1000 == 0)
        INFO(TCPX_ALL, "Call to connect returned %s, retrying",
             strerror(errno));
      usleep(SLEEP_INT);
      goto retry;
    }
  }
  char line1[1024];
  WARN("Connect to %s from %s failed : %s", socketToString(&rAddr.sa, line),
       socketToString(&lAddr.sa, line1), strerror(errno));
  return tcpxSystemError;
}

tcpxResult_t connectAddress(int* fd, union socketAddress* remoteAddr,
                                   union socketAddress* localAddr, int port, bool match_local_port) {
                                    return connectAddressInternal(fd, remoteAddr, localAddr, port, match_local_port);
                                   }

tcpxResult_t connectAddress(int* fd, union socketAddress* remoteAddr,
                                   union socketAddress* localAddr, int port) {
                                    return connectAddress(fd, remoteAddr, localAddr, port, false);
                                   }

tcpxResult_t connectAddress(int* fd, union socketAddress* remoteAddr,
                                   union socketAddress* localAddr) {
  return connectAddress(fd, remoteAddr, localAddr, 0);
}
