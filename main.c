/*
 * Copyright 2018 Joey Hewitt <joey@joeyhewitt.com>
 *
 * This file is part of libqipcrtr4msmipc.
 *
 * libqipcrtr4msmipc is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libqipcrtr4msmipc is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libqipcrtr4msmipc.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/msm_ipc.h>
#include <linux/qrtr.h>

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#define IPC_ROUTER_NID_LOCAL            1 /* from ipc_router.h in MSM kernel fork */

/* helpers */
static int is_socket_msm_ipc(int sockfd);
static int translate_addr_msmipc2qipcrtr(const struct sockaddr *addr, struct sockaddr_qrtr *addr_qrtr);
static int translate_addr_qipcrtr2msmipc(const struct sockaddr *addr, struct sockaddr_msm_ipc *addr_mi);
#define DBG(fmt, ...) do { fprintf(stderr, "libqipcrtr4msmipc %s: " fmt "\n", __FUNCTION__, ##__VA_ARGS__); } while(0)
#define DIE(fmt, ...) do { \
	DBG(fmt, ##__VA_ARGS__); \
	exit(2); \
} while(0)
static inline int min(int a, int b);

/* original functions */
static int (*real_socket)(int domain, int type, int protocol);
static int (*real_bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static int (*real_getsockname)(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
static ssize_t (*real_sendto)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *, socklen_t);
static ssize_t (*real_recvfrom)(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

#define LOAD_DLSYM(n) do { real_##n = dlsym(RTLD_NEXT, #n); } while(0)
__attribute__ ((__constructor__)) static void init() {
	LOAD_DLSYM(socket);
	LOAD_DLSYM(bind);
	LOAD_DLSYM(getsockname);
	LOAD_DLSYM(sendto);
	LOAD_DLSYM(recvfrom);
}

/* state storage */
// TODO store on per-socket basis; for now we assume only one socket per program
static uint32_t g_service = 0, g_instance = 0;

/* intercepted functions */
int socket(int domain, int type, int protocol) {
	return real_socket(domain != AF_QIPCRTR ? domain : AF_MSM_IPC, type, protocol);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	if (addr->sa_family == AF_QIPCRTR) {
		// we don't have enough information to bind on AF_MSM_IPC yet
		return 0;
	} else {
		return real_bind(sockfd, addr, addrlen);
	}
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	// getsockname() on AF_MSM_IPC causes 'Unable to handle kernel NULL pointer dereference at virtual address 00000000'
	if (is_socket_msm_ipc(sockfd)) {
		// we have to lookup with an ioctl to get the node and port we're on
		struct {
			struct server_lookup_args lookup_args;
			struct msm_ipc_server_info srv_info;
		} ioctl_args = {
			.lookup_args = {
				.port_name = { .service = g_service, .instance = g_instance, },
				.num_entries_in_array = 1,
			},
		};
		int rc = ioctl(sockfd, IPC_ROUTER_IOCTL_LOOKUP_SERVER, &ioctl_args);
		if (rc < 0 || ioctl_args.lookup_args.num_entries_found != 1) {
			DBG("server info not found");
			struct sockaddr_qrtr ret = {
				.sq_family = AF_QIPCRTR,
				.sq_node = IPC_ROUTER_NID_LOCAL,
				.sq_port = 0, // XXX we don't know, but a valid sq_node should be good enough for libqrtr in this case
			};
			memcpy(addr, &ret, min(sizeof(ret), *addrlen));
			*addrlen = sizeof(ret);
			return 0;
		}
		DBG("found server at node=%d, port=%d", ioctl_args.srv_info.node_id, ioctl_args.srv_info.port_id);
		struct sockaddr_qrtr ret = {
			.sq_family = AF_QIPCRTR,
			.sq_node = ioctl_args.srv_info.node_id,
			.sq_port = ioctl_args.srv_info.port_id,
		};
		memcpy(addr, &ret, min(sizeof(ret), *addrlen));
		*addrlen = sizeof(ret);
		return 0;
	} else {
		return real_getsockname(sockfd, addr, addrlen);
	}
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
	struct sockaddr_msm_ipc sami;

	if (translate_addr_qipcrtr2msmipc(dest_addr, &sami)) {
		struct sockaddr_qrtr *dest_addr_qrtr = (struct sockaddr_qrtr *)dest_addr;
		const struct qrtr_ctrl_pkt *qrtr_ctrl_pkt = buf;

		if (dest_addr_qrtr->sq_node == IPC_ROUTER_NID_LOCAL && dest_addr_qrtr->sq_port == QRTR_PORT_CTRL &&
			qrtr_ctrl_pkt->cmd == QRTR_TYPE_NEW_SERVER) {

			// translate to bind()
			const struct sockaddr_msm_ipc bind_addr = {
				.family = AF_MSM_IPC,
				.address = {
					.addrtype = MSM_IPC_ADDR_NAME,
					.addr = {
						.port_name = {
							.service = qrtr_ctrl_pkt->server.service,
							.instance = qrtr_ctrl_pkt->server.instance,
						},
					},
				},
			};
			if (real_bind(sockfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
				// leave bind()'s errno for caller
				return -1;
			}
			g_service = qrtr_ctrl_pkt->server.service;
			g_instance = qrtr_ctrl_pkt->server.instance;
			return len; // indicate whole packet was sent
		}

		return real_sendto(sockfd, buf, len, flags, (const struct sockaddr*)&sami, sizeof(sami));
	} else {
		return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	}
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
	ssize_t sz;
	struct sockaddr_msm_ipc sami;
	socklen_t sami_len = sizeof(sami);

	sz = real_recvfrom(sockfd, buf, len, flags, (struct sockaddr*)&sami, &sami_len);

	if (translate_addr_msmipc2qipcrtr((const struct sockaddr *)&sami, (struct sockaddr_qrtr *)src_addr)) {
		*addrlen = sizeof(struct sockaddr_qrtr);
	}

	return sz;
}

/* helpers */
static int translate_addr_msmipc2qipcrtr(const struct sockaddr *addr, struct sockaddr_qrtr *addr_qrtr) {
	if (addr->sa_family != AF_MSM_IPC) {
		return 0;
	}

	const struct sockaddr_msm_ipc *addr_mi = (const struct sockaddr_msm_ipc *)addr;

	if (addr_mi->address.addrtype != MSM_IPC_ADDR_ID) {
		// as far as I can see in the kernel, this won't happen in the usecases we cover
		DIE("got something other than MSM_IPC_ADDR_ID");
	}
	struct sockaddr_qrtr ret = {
		.sq_family = AF_QIPCRTR,
		.sq_node = addr_mi->address.addr.port_addr.node_id,
		.sq_port = addr_mi->address.addr.port_addr.port_id,
	};
	*addr_qrtr = ret;
	return 1;
}

static int translate_addr_qipcrtr2msmipc(const struct sockaddr *addr, struct sockaddr_msm_ipc *addr_mi) {
	if (addr->sa_family != AF_QIPCRTR) {
		return 0;
	}

	const struct sockaddr_qrtr *addr_qrtr = (const struct sockaddr_qrtr *)addr;

	struct sockaddr_msm_ipc ret = {
		.family = AF_MSM_IPC,
		.address = {
			.addrtype = MSM_IPC_ADDR_ID,
			.addr = {
				.port_addr = {
					.node_id = addr_qrtr->sq_node,
					.port_id = addr_qrtr->sq_port,
				},
			},
		},
	};

	*addr_mi = ret;
	return 1;
}

static inline int min(int a, int b) {
	return a < b ? a : b;
}

static int is_socket_msm_ipc(int sockfd) {
	int domain;
	socklen_t length = sizeof(domain);

	if (getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &domain, &length) < 0) {
		return 0;
	}

	return length == sizeof(domain) && domain == AF_MSM_IPC;
}
