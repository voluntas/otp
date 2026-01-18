/*
 * %CopyrightBegin%
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright Ericsson AB 2025. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * %CopyrightEnd%
 *
 * ----------------------------------------------------------------------
 *  Purpose : High-performance io_uring I/O backend for socket.
 * ----------------------------------------------------------------------
 *
 * Design principles:
 * - Per-scheduler io_uring rings to avoid lock contention
 * - Lock-free submission path for maximum throughput
 * - Fire-and-forget UDP sends (no completion tracking)
 * - SQPOLL mode to avoid submit syscalls
 * - Single CQE thread polling all rings via epoll + eventfd
 */

#ifndef SOCKET_URING_H__
#define SOCKET_URING_H__

#ifdef ESOCK_USE_URING

#include <liburing.h>
#include "socket_io.h"

/* ========================================================================
 * io_uring configuration - tuned for high throughput
 */

#define ESURING_RING_SIZE       8192    /* Large SQ ring */
#define ESURING_CQ_SIZE         16384   /* 2x SQ for CQ */

/* Fire-and-forget user_data marker (no completion tracking needed) */
#define ESURING_FIRE_AND_FORGET ((void*)0x1)

/* Pre-allocated pools (per ring instance) */
#define ESURING_SEND_POOL_SIZE  8192    /* Sendto buffer pool (>= ring size) */
#define ESURING_SEND_BUF_SIZE   2048    /* Max packet size for pool */
#define ESURING_IOV_POOL_SIZE   512     /* Sendmsg iovec pool */
#define ESURING_IOV_MAX_ENTRIES 16      /* Max iovec entries per sendmsg */
#define ESURING_IOV_BUF_SIZE    65536   /* Max total data size for sendmsg */

/* Batch submit configuration */
#define ESURING_BATCH_SIZE      64      /* Submit after this many SQEs */

/* sendmmsg configuration */
#define ESURING_MMSG_MAX        1024    /* Max messages per sendmmsg call */
#define ESURING_MMSG_BUF_SIZE   (ESURING_MMSG_MAX * 1500) /* ~1.5MB buffer */

/* ========================================================================
 * Lock-free helpers
 */

static inline void esuring_cpu_relax(void) {
#if defined(__x86_64__) || defined(__i386__)
    __builtin_ia32_pause();
#elif defined(__aarch64__)
    __asm__ volatile("yield" ::: "memory");
#endif
}

/* ========================================================================
 * Sendto buffer entry (fire-and-forget with circular allocation)
 */
typedef struct ESURingSendEntry_ {
    unsigned char           buf[ESURING_SEND_BUF_SIZE];
    size_t                  size;
    ESockAddress            addr;
    SOCKLEN_T               addrLen;
} ESURingSendEntry;

/* ========================================================================
 * Iovec pool entry for sendmsg (fire-and-forget with circular allocation)
 */
typedef struct ESURingIovecEntry_ {
    struct iovec            iov[ESURING_IOV_MAX_ENTRIES];
    struct msghdr           msg;
    ESockAddress            addr;
    unsigned char           buf[ESURING_IOV_BUF_SIZE];  /* Data buffer */
    size_t                  buf_used;                    /* Bytes used in buf */
} ESURingIovecEntry;

/* Forward declaration for pending list */
struct ESURingRecvOp_;
typedef struct ESURingRecvOp_ ESURingRecvOp;

/* ========================================================================
 * Per-scheduler ring instance
 *
 * Each normal scheduler has its own ring instance (no mutex needed).
 * Ring index 0 is shared by dirty schedulers and requires mutex protection.
 */
typedef struct {
    struct io_uring     ring;
    int                 eventfd;        /* For CQE notification to epoll */
    unsigned int        pending_submits; /* Count of SQEs pending submit */
    BOOLEAN_T           sqpoll;         /* TRUE if using SQPOLL mode */
    BOOLEAN_T           need_mutex;     /* TRUE if this ring needs mutex (index 0) */
    ErlNifMutex*        ring_mtx;       /* Only used if need_mutex is TRUE */

    /* Sendto buffer pool (circular allocation, no free list needed) */
    ESURingSendEntry*   send_pool;
    unsigned int        send_next_idx;  /* Circular index for allocation */

    /* Iovec pool for sendmsg (circular allocation, no free list needed) */
    ESURingIovecEntry*  iov_pool;
    unsigned int        iov_next_idx;   /* Circular index for allocation */

    /* Pending recvfrom operations (for cancellation) */
    ESURingRecvOp*      pending_recvs;
    ErlNifMutex*        pending_mtx;

    /* Per-ring statistics */
    volatile unsigned long stat_sendto;
    volatile unsigned long stat_sendmsg;
    volatile unsigned long stat_sendmmsg;
    volatile unsigned long stat_sendmmsg_msgs;
    volatile unsigned long stat_recvfrom;
    volatile unsigned long stat_ring_full;
    volatile unsigned long stat_direct_syscall;
} ESURingInstance;

/* ========================================================================
 * Global control structure
 *
 * Manages all ring instances and the single CQE processing thread.
 */
/* Maximum number of SQPOLL groups (each group shares one SQPOLL thread) */
#define ESURING_MAX_SQPOLL_GROUPS 4

typedef struct {
    ESURingInstance*    rings;          /* Array of ring instances */
    unsigned int        num_rings;      /* Number of rings (schedulers + 1) */
    int                 epoll_fd;       /* epoll for CQE notifications */
    int                 sqpoll_parent_fds[ESURING_MAX_SQPOLL_GROUPS]; /* Parent ring fd per group */
    unsigned int        num_sqpoll_groups; /* Actual number of SQPOLL groups */
    ErlNifTid           cqe_tid;        /* Single CQE polling thread */
    volatile int        running;        /* Thread running flag */
    BOOLEAN_T           dbg;
    BOOLEAN_T           sockDbg;

    /* Global statistics */
    volatile unsigned long stat_cqe_processed;
    volatile unsigned long stat_sqpoll_shared;  /* Rings sharing SQPOLL */
} ESURingGlobal;

/* ========================================================================
 * RecvFrom operation data (needs completion tracking)
 */
struct ESURingRecvOp_ {
    ErlNifPid           caller;
    ErlNifEnv*          env;
    struct msghdr       msg;
    struct iovec        iov[1];
    ErlNifBinary        buf;
    ESockAddress        fromAddr;
    ERL_NIF_TERM        sockRef;
    ERL_NIF_TERM        recvRef;
    volatile int        cancelled;              /* Set when cancelled */
    struct ESURingRecvOp_* next;                /* Link for pending list */
};

/* ========================================================================
 * Function declarations
 */

extern int  esuring_init(unsigned int numThreads, const ESockData* dataP);
extern void esuring_finish(void);
extern ERL_NIF_TERM esuring_info(ErlNifEnv* env);

extern ERL_NIF_TERM esuring_recvfrom(ErlNifEnv*       env,
                                     ESockDescriptor* descP,
                                     ERL_NIF_TERM     sockRef,
                                     ERL_NIF_TERM     recvRef,
                                     ssize_t          len,
                                     int              flags);

extern ERL_NIF_TERM esuring_sendto(ErlNifEnv*       env,
                                   ESockDescriptor* descP,
                                   ERL_NIF_TERM     sockRef,
                                   ERL_NIF_TERM     sendRef,
                                   ErlNifBinary*    dataP,
                                   int              flags,
                                   ESockAddress*    toAddrP,
                                   SOCKLEN_T        toAddrLen);

extern ERL_NIF_TERM esuring_sendmsg(ErlNifEnv*       env,
                                    ESockDescriptor* descP,
                                    ERL_NIF_TERM     sockRef,
                                    ERL_NIF_TERM     sendRef,
                                    ERL_NIF_TERM     eMsg,
                                    int              flags,
                                    ERL_NIF_TERM     eIOV,
                                    const ESockData* dataP);

extern ERL_NIF_TERM esuring_cancel_recv(ErlNifEnv*       env,
                                        ESockDescriptor* descP,
                                        ERL_NIF_TERM     sockRef,
                                        ERL_NIF_TERM     opRef);

extern ERL_NIF_TERM esuring_cancel_send(ErlNifEnv*       env,
                                        ESockDescriptor* descP,
                                        ERL_NIF_TERM     sockRef,
                                        ERL_NIF_TERM     opRef);

/* ========================================================================
 * sendmmsg - batch send multiple messages with io_uring
 *
 * eMsgs: list of #{iov => IOV, addr => Addr} maps
 * Returns: {ok, SentCount} | {error, Reason}
 */
extern ERL_NIF_TERM esuring_sendmmsg(ErlNifEnv*       env,
                                     ESockDescriptor* descP,
                                     ERL_NIF_TERM     sockRef,
                                     ERL_NIF_TERM     sendRef,
                                     ERL_NIF_TERM     eMsgs,
                                     int              flags,
                                     const ESockData* dataP);

#endif /* ESOCK_USE_URING */

#endif /* SOCKET_URING_H__ */
