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

#include "netdev_bridge.h"

#include <linux/genetlink.h>

#include "../adapter/debug1.h"
#include "../macro.h"

#define NETDEV_CMD_BIND_RX 13
#define NETDEV_CMD_BIND_TX 15
#define NETDEV_A_DMABUF_IFINDEX 1
#define NETDEV_A_DMABUF_FD 3
#define NETDEV_A_DMABUF_ID 4
#define NETDEV_BIND_TX_REPLY_ATTR_MAX NETDEV_A_DMABUF_ID

// Macro to iterate through the mnl nested attributes
// Resembles libmnl's mnl_attr_for_each_nested, but it
// fixes the void* cast issue for mnl_attr_get_payload.
#define mnl_for_each_nested_attr(attr, nest) \
  for ((attr) = (struct nlattr*) mnl_attr_get_payload(nest); \
       mnl_attr_ok((attr), (char *)mnl_attr_get_payload(nest) + \
       mnl_attr_get_payload_len(nest) - (char *)(attr)); \
       (attr) = mnl_attr_next(attr))

static int parse_family_ops_cb(const struct nlattr* attr, void* data) {
  const struct nlattr** tb = (const struct nlattr**)data;
  int type = mnl_attr_get_type(attr);

  if (mnl_attr_type_valid(attr, CTRL_ATTR_OP_MAX) < 0)
    return MNL_CB_OK;

  switch(type) {
  case CTRL_ATTR_OP_ID:
    if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
        INFO(TCPX_INIT | TCPX_NET,
             "NET/" PRODUCT_NAME " : Invalid mnl attribute");
      return MNL_CB_ERROR;
    }
    break;
  case CTRL_ATTR_OP_MAX:
    break;
  default:
    return MNL_CB_OK;
  }
  tb[type] = attr;
  return MNL_CB_OK;
}

static bool parse_genl_family_ops(struct nlattr* nest) {
  struct nlattr* attr;
  bool is_netdev_bind_rx = false;
  bool is_netdev_bind_tx = false;

  mnl_for_each_nested_attr(attr, nest) {
    struct nlattr* tb[CTRL_ATTR_OP_MAX+1] = {};
    mnl_attr_parse_nested(attr, parse_family_ops_cb, tb);
    uint32_t op_id = mnl_attr_get_u32(tb[CTRL_ATTR_OP_ID]);
    if (op_id == NETDEV_CMD_BIND_RX) {
      is_netdev_bind_rx = true;
    } else if (op_id == NETDEV_CMD_BIND_TX) {
      is_netdev_bind_tx = true;
    }
  }

  return is_netdev_bind_rx && is_netdev_bind_tx;
}

int family_data_attr_cb(const struct nlattr* attr, void* data) {
  const struct nlattr** tb = (const struct nlattr**)data;
  int type = mnl_attr_get_type(attr);

  if (mnl_attr_type_valid(attr, CTRL_ATTR_MAX) < 0) return MNL_CB_OK;

  switch (type) {
    case CTRL_ATTR_FAMILY_NAME:
      if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
        INFO(TCPX_INIT | TCPX_NET,
             "NET/" PRODUCT_NAME " : Invalid mnl attribute");
        return MNL_CB_ERROR;
      }
      break;
    case CTRL_ATTR_FAMILY_ID:
      if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
        INFO(TCPX_INIT | TCPX_NET,
             "NET/" PRODUCT_NAME " : Invalid mnl attribute");
        return MNL_CB_ERROR;
      }
      break;
    case CTRL_ATTR_VERSION:
    case CTRL_ATTR_HDRSIZE:
    case CTRL_ATTR_MAXATTR:
      if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
        INFO(TCPX_INIT | TCPX_NET,
             "NET/" PRODUCT_NAME " : Invalid mnl attribute");
        return MNL_CB_ERROR;
      }
      break;
    case CTRL_ATTR_OPS:
    case CTRL_ATTR_MCAST_GROUPS:
      if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
        INFO(TCPX_INIT | TCPX_NET,
             "NET/" PRODUCT_NAME " : Invalid mnl attribute");
        return MNL_CB_ERROR;
      }
      break;
  }
  tb[type] = attr;
  return MNL_CB_OK;
}

int family_cb(const struct nlmsghdr* nlh, void* data) {
  int* family_id = (int*)data;
  struct nlattr* tb[CTRL_ATTR_MAX + 1] = {};

  struct genlmsghdr* genlh = (struct genlmsghdr*)mnl_nlmsg_get_payload(nlh);
  mnl_attr_parse(nlh, sizeof(*genlh), family_data_attr_cb, tb);

  if (tb[CTRL_ATTR_FAMILY_ID]) {
    uint16_t netdev_family_id = mnl_attr_get_u16(tb[CTRL_ATTR_FAMILY_ID]);
    *family_id = netdev_family_id;
  } else {
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : family_cb() error resolving family id");
    return MNL_CB_ERROR;
  }

  if (tb[CTRL_ATTR_OPS]) {
    if (!parse_genl_family_ops(tb[CTRL_ATTR_OPS])) {
      INFO(TCPX_INIT | TCPX_NET,
           "NET/" PRODUCT_NAME " : family_cb() netdev ops not supported,"
           " removing family ID");
      // Reset family_id to ensure the netdev init fails
      // in case the netdev ops are not supported.
      *family_id = -1;
      return MNL_CB_ERROR;
    }
  }

  return MNL_CB_OK;
}

int bind_reply_attr_cb(const struct nlattr* attr, void* data) {
  const struct nlattr** tb = (const struct nlattr**)data;
  int type = mnl_attr_get_type(attr);

  if (type > 0 && type <= NETDEV_BIND_TX_REPLY_ATTR_MAX) {
    tb[type] = attr;
  }
  return MNL_CB_OK;
}

int bind_reply_cb(const struct nlmsghdr* nlh, void* data) {
  struct genlmsghdr* genlh = (struct genlmsghdr*)mnl_nlmsg_get_payload(nlh);
  struct nlattr* tb[NETDEV_BIND_TX_REPLY_ATTR_MAX + 1];

  memset(tb, 0, sizeof(tb));

  if (genlh->cmd != NETDEV_CMD_BIND_TX) {
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : bind_reply_cb() Ignoring unexpected message"
         " (type %u, cmd %u).", nlh->nlmsg_type, genlh->cmd);
    return MNL_CB_ERROR;
  }

  if (mnl_attr_parse(nlh, sizeof(*genlh), bind_reply_attr_cb, tb) < 0) {
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : bind_reply_cb() Failed to parse attributes"
         " in reply.");
    return MNL_CB_ERROR;
  }

  int* output_id = (int*)data;
  if (!tb[NETDEV_A_DMABUF_ID]) {
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : bind_reply_cb() Cannot find the dmabuf id");
    return MNL_CB_ERROR;
  }
  *output_id = mnl_attr_get_u32(tb[NETDEV_A_DMABUF_ID]);
  return MNL_CB_STOP;
}

int NetdevBridge::initNetdevBridge() {
  int family_id = -1;
  int ret = -1;
  char buf[MNL_SOCKET_BUFFER_SIZE];

  nl_ = mnl_socket_open(NETLINK_GENERIC);
  if (nl_ == nullptr) {
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : initNetdevBridge() Cannot open netlink socket!");
    return ret;
  }
  if (mnl_socket_bind(nl_, 0, MNL_SOCKET_AUTOPID) < 0) {
    mnl_socket_close(nl_);
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : initNetdevBridge() Cannot bind to netlink socket!");
    return ret;
  }

  unsigned int portid = mnl_socket_get_portid(nl_);
  struct nlmsghdr* nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = GENL_ID_CTRL;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq = seq_;

  struct genlmsghdr* genlh =
      (struct genlmsghdr*)mnl_nlmsg_put_extra_header(nlh, sizeof(genlmsghdr));
  genlh->cmd = CTRL_CMD_GETFAMILY;
  genlh->version = 1;

  mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, "netdev");

  ret = mnl_socket_sendto(nl_, nlh, nlh->nlmsg_len);
  if (ret < 0) {
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : initNetdevBridge() mnl socket send error");
    return ret;
  }

  ret = mnl_socket_recvfrom(nl_, buf, sizeof(buf));
  if (ret < 0) {
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : initNetdevBridge() mnl socket recv error");
    return ret;
  }

  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, seq_, portid, family_cb, &family_id);
    if (ret <= 0) break;
    ret = mnl_socket_recvfrom(nl_, buf, sizeof(buf));
  }
  if (family_id == -1) {
    INFO(TCPX_INIT | TCPX_NET,
         "NET/" PRODUCT_NAME " : initNetdevBridge() invalid mnl family with bind TX/RX ops");
    return family_id;
  }

  familyId_ = family_id;
  isInited_ = true;

  return family_id;
}

void NetdevBridge::destroyNetdevBridge() {
    if (nl_ != nullptr) {
      mnl_socket_close(nl_);
      nl_ = nullptr;
    }
    familyId_ = -1;
    seq_ = 0;
    isInited_ = false;
    dmaBufId_ = -1;
}

int NetdevBridge::bindTx(uint32_t ifindex, uint32_t dmabuf_fd) {
  char buf[MNL_SOCKET_BUFFER_SIZE];
  int ret = -1;

  struct nlmsghdr* nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = familyId_;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nlh->nlmsg_seq = ++seq_;

  struct genlmsghdr* genlh =
      (struct genlmsghdr*)mnl_nlmsg_put_extra_header(nlh, sizeof(*genlh));
  genlh->cmd = NETDEV_CMD_BIND_TX;
  genlh->version = 1;

  mnl_attr_put_u32(nlh, NETDEV_A_DMABUF_IFINDEX, (uint32_t)ifindex);
  mnl_attr_put_u32(nlh, NETDEV_A_DMABUF_FD, dmabuf_fd);

  ret = mnl_socket_sendto(nl_, nlh, nlh->nlmsg_len);
  if (ret < 0) {
    INFO(TCPX_INIT | TCPX_NET, "NET/" PRODUCT_NAME "bind_tx() nl socket sendto failed");
    return ret;
  }

  unsigned int local_portid = mnl_socket_get_portid(nl_);
  int output_id = -1;

  ret = mnl_socket_recvfrom(nl_, buf, sizeof(buf));
  if (ret < 0) {
    INFO(TCPX_INIT | TCPX_NET, "NET/" PRODUCT_NAME "bind_tx() nl socket recv failed");
    return ret;
  }

  while (ret > 0) {
    ret = mnl_cb_run(buf, ret, seq_, local_portid, bind_reply_cb, &output_id);
    if (ret <= 0) break;
    ret = mnl_socket_recvfrom(nl_, buf, sizeof(buf));
  }

  if (output_id < 0) {
    INFO(TCPX_INIT | TCPX_NET, "NET/" PRODUCT_NAME "bind_tx() Invalid recv output id");
  }

  dmaBufId_ = output_id;

  return output_id;
}
