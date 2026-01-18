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
 *  High-performance io_uring I/O backend for socket NIFs.
 * ----------------------------------------------------------------------
 *
 * Key optimizations:
 * 1. Per-scheduler io_uring rings - no lock contention between schedulers
 * 2. Fire-and-forget UDP sends - no completion tracking overhead
 * 3. SQPOLL mode to avoid submit syscalls
 * 4. Single CQE thread polling all rings via epoll + eventfd
 * 5. Pre-allocated buffer pools for sendto/sendmsg
 */

#ifdef HAVE_CONFIG_H
#    include "config.h"
#endif

#ifdef ESOCK_USE_URING

#ifndef WANT_NONBLOCKING
#define WANT_NONBLOCKING
#endif
#include "sys.h"

#include <liburing.h>
#include <string.h>
#include <errno.h>
#include <sched.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "global.h"  /* For erts_get_scheduler_id(), erts_no_schedulers */
#include "prim_socket_int.h"
#include "socket_util.h"
#include "socket_io.h"
#include "socket_uring.h"

/* ========================================================================
 * Global state
 */

static ESURingGlobal gctrl;

/* Debug macro */
#define SGDBG(proto) ESOCK_DBG_PRINTF(gctrl.dbg, proto)

/* ========================================================================
 * Forward declarations
 */

static int   esuring_init_ring(ESURingInstance* inst, unsigned int idx);
static void  esuring_destroy_ring(ESURingInstance* inst);
static void* esuring_cqe_thread(void* arg);
static void  esuring_process_cqe(ESURingInstance* inst, struct io_uring_cqe* cqe);
static void  esuring_drain_cqe(ESURingInstance* inst);

/* Get ring index for current scheduler */
static inline unsigned int esuring_get_ring_idx(void) {
    Uint id = erts_get_scheduler_id();
    /* id=0 for dirty/other, id=1..N for normal schedulers */
    if (id >= gctrl.num_rings)
        id = 0;  /* Safety fallback */
    return (unsigned int)id;
}

/* Get ring instance for current scheduler */
static inline ESURingInstance* esuring_get_ring(void) {
    return &gctrl.rings[esuring_get_ring_idx()];
}

/* ========================================================================
 * Initialize a single ring instance
 */

static int
esuring_init_ring(ESURingInstance* inst, unsigned int idx)
{
    struct io_uring_params params;
    int ret;
    unsigned int group_idx;
    unsigned int rings_per_group;

    memset(inst, 0, sizeof(*inst));
    inst->eventfd = -1;
    inst->need_mutex = (idx == 0);  /* Only ring 0 needs mutex (dirty schedulers) */

    /*
     * SQPOLL strategy with ATTACH_WQ for shared SQPOLL threads:
     * - Ring 0 (dirty): COOP_TASKRUN (low frequency, uses mutex)
     * - Normal scheduler rings: Grouped into SQPOLL groups
     *   - Each group has 1 parent ring + attached child rings
     *   - Groups share SQPOLL threads via ATTACH_WQ
     *   - Number of groups = min(schedulers/2, MAX_SQPOLL_GROUPS)
     *
     * This balances between reducing SQPOLL threads and avoiding bottlenecks.
     */
    memset(&params, 0, sizeof(params));

    if (idx == 0) {
        goto try_coop_taskrun;
    }

    /* Calculate which SQPOLL group this ring belongs to */
    /* rings_per_group determines how many rings share one SQPOLL thread */
    rings_per_group = (gctrl.num_rings > 5) ? 2 : 1;  /* 2 rings per SQPOLL thread */
    group_idx = (idx - 1) / rings_per_group;
    if (group_idx >= ESURING_MAX_SQPOLL_GROUPS) {
        group_idx = ESURING_MAX_SQPOLL_GROUPS - 1;  /* Cap to max groups */
    }

    if (gctrl.sqpoll_parent_fds[group_idx] < 0) {
        /* This ring becomes the parent for this SQPOLL group */
        params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER;
        params.sq_thread_idle = 2000;  /* 2 seconds idle before sleeping */

        ret = io_uring_queue_init_params(ESURING_RING_SIZE, &inst->ring, &params);
        if (ret >= 0) {
            inst->sqpoll = TRUE;
            gctrl.sqpoll_parent_fds[group_idx] = inst->ring.ring_fd;
            gctrl.num_sqpoll_groups++;
            SGDBG(("ESURING", "Ring %u: SQPOLL parent for group %u (fd=%d)\r\n",
                   idx, group_idx, inst->ring.ring_fd));
        } else {
            SGDBG(("ESURING", "Ring %u: SQPOLL failed (%d), trying COOP_TASKRUN\r\n",
                   idx, ret));
            goto try_coop_taskrun;
        }
    } else {
        /* Attach to the parent ring of this group */
        params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_ATTACH_WQ | IORING_SETUP_SINGLE_ISSUER;
        params.wq_fd = gctrl.sqpoll_parent_fds[group_idx];
        params.sq_thread_idle = 2000;

        ret = io_uring_queue_init_params(ESURING_RING_SIZE, &inst->ring, &params);
        if (ret >= 0) {
            inst->sqpoll = TRUE;
            __atomic_fetch_add(&gctrl.stat_sqpoll_shared, 1, __ATOMIC_RELAXED);
            SGDBG(("ESURING", "Ring %u: SQPOLL attached to group %u (wq_fd=%d)\r\n",
                   idx, group_idx, gctrl.sqpoll_parent_fds[group_idx]));
        } else {
            /* ATTACH_WQ failed, try independent SQPOLL */
            SGDBG(("ESURING", "Ring %u: ATTACH_WQ failed (%d), trying independent SQPOLL\r\n",
                   idx, ret));
            memset(&params, 0, sizeof(params));
            params.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER;
            params.sq_thread_idle = 2000;

            ret = io_uring_queue_init_params(ESURING_RING_SIZE, &inst->ring, &params);
            if (ret >= 0) {
                inst->sqpoll = TRUE;
                SGDBG(("ESURING", "Ring %u: Independent SQPOLL\r\n", idx));
            } else {
                goto try_coop_taskrun;
            }
        }
    }

    goto ring_init_done;

try_coop_taskrun:
    /* Ring 0 or fallback: Use COOP_TASKRUN */
    memset(&params, 0, sizeof(params));
    params.flags = IORING_SETUP_COOP_TASKRUN;
    ret = io_uring_queue_init_params(ESURING_RING_SIZE, &inst->ring, &params);

    if (ret >= 0) {
        inst->sqpoll = FALSE;
        SGDBG(("ESURING", "Ring %u: COOP_TASKRUN mode\r\n", idx));
    } else {
        /* Try basic init */
        memset(&params, 0, sizeof(params));
        ret = io_uring_queue_init_params(ESURING_RING_SIZE, &inst->ring, &params);

        if (ret < 0) {
            SGDBG(("ESURING", "Ring %u: io_uring init failed: %d\r\n", idx, ret));
            return ret;
        }
        inst->sqpoll = FALSE;
        SGDBG(("ESURING", "Ring %u: Basic mode\r\n", idx));
    }

ring_init_done:

    /* Create eventfd for CQE notifications */
    inst->eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (inst->eventfd < 0) {
        io_uring_queue_exit(&inst->ring);
        return -errno;
    }

    /* Register eventfd with io_uring */
    ret = io_uring_register_eventfd(&inst->ring, inst->eventfd);
    if (ret < 0) {
        close(inst->eventfd);
        io_uring_queue_exit(&inst->ring);
        return ret;
    }

    /* Create mutex if needed (only for ring 0) */
    if (inst->need_mutex) {
        char name[32];
        snprintf(name, sizeof(name), "esuring_ring_%u", idx);
        inst->ring_mtx = enif_mutex_create(name);
        if (inst->ring_mtx == NULL) {
            close(inst->eventfd);
            io_uring_queue_exit(&inst->ring);
            return -ENOMEM;
        }
    }

    /* Allocate sendto buffer pool */
    inst->send_pool = enif_alloc(sizeof(ESURingSendEntry) * ESURING_SEND_POOL_SIZE);
    if (inst->send_pool == NULL) {
        if (inst->ring_mtx) enif_mutex_destroy(inst->ring_mtx);
        close(inst->eventfd);
        io_uring_queue_exit(&inst->ring);
        return -ENOMEM;
    }
    inst->send_next_idx = 0;

    /* Allocate iovec pool for sendmsg */
    inst->iov_pool = enif_alloc(sizeof(ESURingIovecEntry) * ESURING_IOV_POOL_SIZE);
    if (inst->iov_pool == NULL) {
        enif_free(inst->send_pool);
        if (inst->ring_mtx) enif_mutex_destroy(inst->ring_mtx);
        close(inst->eventfd);
        io_uring_queue_exit(&inst->ring);
        return -ENOMEM;
    }
    inst->iov_next_idx = 0;

    /* Initialize pending recv list */
    inst->pending_recvs = NULL;
    {
        char name[32];
        snprintf(name, sizeof(name), "esuring_pending_%u", idx);
        inst->pending_mtx = enif_mutex_create(name);
    }
    if (inst->pending_mtx == NULL) {
        enif_free(inst->iov_pool);
        enif_free(inst->send_pool);
        if (inst->ring_mtx) enif_mutex_destroy(inst->ring_mtx);
        close(inst->eventfd);
        io_uring_queue_exit(&inst->ring);
        return -ENOMEM;
    }

    return 0;
}

/* ========================================================================
 * Destroy a single ring instance
 */

static void
esuring_destroy_ring(ESURingInstance* inst)
{
    if (inst->pending_mtx != NULL) {
        enif_mutex_destroy(inst->pending_mtx);
        inst->pending_mtx = NULL;
    }

    if (inst->iov_pool != NULL) {
        enif_free(inst->iov_pool);
        inst->iov_pool = NULL;
    }

    if (inst->send_pool != NULL) {
        enif_free(inst->send_pool);
        inst->send_pool = NULL;
    }

    if (inst->ring_mtx != NULL) {
        enif_mutex_destroy(inst->ring_mtx);
        inst->ring_mtx = NULL;
    }

    if (inst->eventfd >= 0) {
        close(inst->eventfd);
        inst->eventfd = -1;
    }

    io_uring_queue_exit(&inst->ring);
}

/* ========================================================================
 * Initialization
 */

extern int
esuring_init(unsigned int numThreads, const ESockData* dataP)
{
    unsigned int i;
    int ret;
    struct epoll_event ev;

    (void)numThreads;

    unsigned int grp;

    memset(&gctrl, 0, sizeof(gctrl));
    gctrl.dbg = dataP->dbg;
    gctrl.sockDbg = dataP->sockDbg;
    gctrl.epoll_fd = -1;
    for (grp = 0; grp < ESURING_MAX_SQPOLL_GROUPS; grp++) {
        gctrl.sqpoll_parent_fds[grp] = -1;
    }
    gctrl.num_sqpoll_groups = 0;

    /* Number of rings = schedulers + 1 (index 0 for dirty/other) */
    gctrl.num_rings = erts_no_schedulers + 1;

    SGDBG(("ESURING", "Initializing %u rings (schedulers=%u)\r\n",
           gctrl.num_rings, (unsigned int)erts_no_schedulers));

    /* Allocate ring array */
    gctrl.rings = enif_alloc(sizeof(ESURingInstance) * gctrl.num_rings);
    if (gctrl.rings == NULL) {
        return ESOCK_IO_ERR_UNSUPPORTED;
    }
    memset(gctrl.rings, 0, sizeof(ESURingInstance) * gctrl.num_rings);

    /* Create epoll instance */
    gctrl.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (gctrl.epoll_fd < 0) {
        enif_free(gctrl.rings);
        gctrl.rings = NULL;
        return ESOCK_IO_ERR_UNSUPPORTED;
    }

    /* Initialize each ring */
    for (i = 0; i < gctrl.num_rings; i++) {
        ret = esuring_init_ring(&gctrl.rings[i], i);
        if (ret < 0) {
            SGDBG(("ESURING", "Failed to init ring %u: %d\r\n", i, ret));
            /* Cleanup already initialized rings */
            while (i > 0) {
                i--;
                epoll_ctl(gctrl.epoll_fd, EPOLL_CTL_DEL,
                          gctrl.rings[i].eventfd, NULL);
                esuring_destroy_ring(&gctrl.rings[i]);
            }
            close(gctrl.epoll_fd);
            enif_free(gctrl.rings);
            gctrl.rings = NULL;
            return ESOCK_IO_ERR_UNSUPPORTED;
        }

        /* Add eventfd to epoll */
        ev.events = EPOLLIN;
        ev.data.u32 = i;  /* Ring index */
        if (epoll_ctl(gctrl.epoll_fd, EPOLL_CTL_ADD,
                      gctrl.rings[i].eventfd, &ev) < 0) {
            esuring_destroy_ring(&gctrl.rings[i]);
            while (i > 0) {
                i--;
                epoll_ctl(gctrl.epoll_fd, EPOLL_CTL_DEL,
                          gctrl.rings[i].eventfd, NULL);
                esuring_destroy_ring(&gctrl.rings[i]);
            }
            close(gctrl.epoll_fd);
            enif_free(gctrl.rings);
            gctrl.rings = NULL;
            return ESOCK_IO_ERR_UNSUPPORTED;
        }
    }

    /* Start CQE processing thread */
    gctrl.running = TRUE;
    ret = enif_thread_create("esuring_cqe", &gctrl.cqe_tid,
                             esuring_cqe_thread, &gctrl, NULL);
    if (ret != 0) {
        gctrl.running = FALSE;
        for (i = 0; i < gctrl.num_rings; i++) {
            epoll_ctl(gctrl.epoll_fd, EPOLL_CTL_DEL,
                      gctrl.rings[i].eventfd, NULL);
            esuring_destroy_ring(&gctrl.rings[i]);
        }
        close(gctrl.epoll_fd);
        enif_free(gctrl.rings);
        gctrl.rings = NULL;
        return ESOCK_IO_ERR_UNSUPPORTED;
    }

    SGDBG(("ESURING", "io_uring backend initialized with %u rings, "
           "%u SQPOLL groups, %lu attached rings\r\n",
           gctrl.num_rings, gctrl.num_sqpoll_groups, gctrl.stat_sqpoll_shared));

    return ESOCK_IO_OK;
}

/* ========================================================================
 * Shutdown
 */

extern void
esuring_finish(void)
{
    unsigned int i;
    struct io_uring_sqe* sqe;

    if (!gctrl.running)
        return;

    /* Signal CQE thread to exit */
    gctrl.running = FALSE;

    /* Send a NOP to wake up any waiting ring */
    if (gctrl.num_rings > 0 && gctrl.rings != NULL) {
        ESURingInstance* inst = &gctrl.rings[0];
        if (inst->need_mutex && inst->ring_mtx)
            enif_mutex_lock(inst->ring_mtx);
        sqe = io_uring_get_sqe(&inst->ring);
        if (sqe != NULL) {
            io_uring_prep_nop(sqe);
            io_uring_sqe_set_data(sqe, NULL);
            io_uring_submit(&inst->ring);
        }
        if (inst->need_mutex && inst->ring_mtx)
            enif_mutex_unlock(inst->ring_mtx);
    }

    enif_thread_join(gctrl.cqe_tid, NULL);

    /* Cleanup all rings */
    for (i = 0; i < gctrl.num_rings; i++) {
        if (gctrl.epoll_fd >= 0 && gctrl.rings[i].eventfd >= 0) {
            epoll_ctl(gctrl.epoll_fd, EPOLL_CTL_DEL,
                      gctrl.rings[i].eventfd, NULL);
        }
        esuring_destroy_ring(&gctrl.rings[i]);
    }

    if (gctrl.epoll_fd >= 0) {
        close(gctrl.epoll_fd);
        gctrl.epoll_fd = -1;
    }

    if (gctrl.rings != NULL) {
        enif_free(gctrl.rings);
        gctrl.rings = NULL;
    }
}

/* ========================================================================
 * Info
 */

extern ERL_NIF_TERM
esuring_info(ErlNifEnv* env)
{
    ERL_NIF_TERM keys[14], vals[14];
    ERL_NIF_TERM info;
    unsigned int i, sqpoll_count = 0;
    unsigned long total_sendto = 0, total_sendmsg = 0, total_recvfrom = 0;
    unsigned long total_sendmmsg = 0, total_sendmmsg_msgs = 0;
    unsigned long total_ring_full = 0, total_direct_syscall = 0;

    /* Aggregate statistics from all rings */
    for (i = 0; i < gctrl.num_rings; i++) {
        ESURingInstance* inst = &gctrl.rings[i];
        total_sendto += inst->stat_sendto;
        total_sendmsg += inst->stat_sendmsg;
        total_sendmmsg += inst->stat_sendmmsg;
        total_sendmmsg_msgs += inst->stat_sendmmsg_msgs;
        total_recvfrom += inst->stat_recvfrom;
        total_ring_full += inst->stat_ring_full;
        total_direct_syscall += inst->stat_direct_syscall;
        if (inst->sqpoll) sqpoll_count++;
    }

    keys[0] = enif_make_atom(env, "backend");
    vals[0] = enif_make_atom(env, "io_uring");

    keys[1] = enif_make_atom(env, "num_rings");
    vals[1] = enif_make_uint(env, gctrl.num_rings);

    keys[2] = enif_make_atom(env, "sqpoll");
    /* Report sqpoll status of ring 1 (first normal scheduler ring) */
    vals[2] = (gctrl.num_rings > 1 && gctrl.rings[1].sqpoll) ?
              esock_atom_true : esock_atom_false;

    keys[3] = enif_make_atom(env, "sqpoll_rings");
    vals[3] = enif_make_uint(env, sqpoll_count);

    keys[4] = enif_make_atom(env, "sqpoll_groups");
    vals[4] = enif_make_uint(env, gctrl.num_sqpoll_groups);

    keys[5] = enif_make_atom(env, "ring_size");
    vals[5] = enif_make_uint(env, ESURING_RING_SIZE);

    keys[6] = enif_make_atom(env, "sendto_count");
    vals[6] = enif_make_uint64(env, total_sendto);

    keys[7] = enif_make_atom(env, "sendmsg_count");
    vals[7] = enif_make_uint64(env, total_sendmsg);

    keys[8] = enif_make_atom(env, "sendmmsg_calls");
    vals[8] = enif_make_uint64(env, total_sendmmsg);

    keys[9] = enif_make_atom(env, "sendmmsg_msgs");
    vals[9] = enif_make_uint64(env, total_sendmmsg_msgs);

    keys[10] = enif_make_atom(env, "recvfrom_count");
    vals[10] = enif_make_uint64(env, total_recvfrom);

    keys[11] = enif_make_atom(env, "ring_full_count");
    vals[11] = enif_make_uint64(env, total_ring_full);

    keys[12] = enif_make_atom(env, "direct_syscall_count");
    vals[12] = enif_make_uint64(env, total_direct_syscall);

    keys[13] = enif_make_atom(env, "cqe_processed");
    vals[13] = enif_make_uint64(env, gctrl.stat_cqe_processed);

    enif_make_map_from_arrays(env, keys, vals, 14, &info);
    return info;
}

/* ========================================================================
 * CQE Processing Thread
 *
 * Single thread polling all rings via epoll + eventfd.
 */

static void*
esuring_cqe_thread(void* arg)
{
    ESURingGlobal* gp = (ESURingGlobal*)arg;
    struct epoll_event events[16];
    int nfds, i;
    uint64_t efd_val;

    while (gp->running) {
        nfds = epoll_wait(gp->epoll_fd, events, 16, 100);  /* 100ms timeout */

        if (nfds < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (nfds == 0) {
            /* Timeout - flush pending submits on all non-SQPOLL rings */
            for (i = 0; (unsigned int)i < gp->num_rings; i++) {
                ESURingInstance* inst = &gp->rings[i];
                if (!inst->sqpoll && inst->pending_submits > 0) {
                    if (inst->need_mutex)
                        enif_mutex_lock(inst->ring_mtx);
                    if (inst->pending_submits > 0) {
                        io_uring_submit(&inst->ring);
                        inst->pending_submits = 0;
                    }
                    if (inst->need_mutex)
                        enif_mutex_unlock(inst->ring_mtx);
                }
            }
            continue;
        }

        for (i = 0; i < nfds; i++) {
            unsigned int ring_idx = events[i].data.u32;
            ESURingInstance* inst;
            struct io_uring_cqe* cqe;

            if (ring_idx >= gp->num_rings)
                continue;

            inst = &gp->rings[ring_idx];

            /* Consume eventfd notification */
            if (read(inst->eventfd, &efd_val, sizeof(efd_val)) < 0) {
                /* Ignore errors (EAGAIN etc) */
            }

            /* Process all available CQEs for this ring */
            while (io_uring_peek_cqe(&inst->ring, &cqe) == 0) {
                esuring_process_cqe(inst, cqe);
                io_uring_cqe_seen(&inst->ring, cqe);
            }
        }
    }

    /* Drain remaining CQEs from all rings */
    for (i = 0; (unsigned int)i < gp->num_rings; i++) {
        ESURingInstance* inst = &gp->rings[i];
        struct io_uring_cqe* cqe;
        while (io_uring_peek_cqe(&inst->ring, &cqe) == 0) {
            esuring_process_cqe(inst, cqe);
            io_uring_cqe_seen(&inst->ring, cqe);
        }
    }

    return NULL;
}

static void
esuring_process_cqe(ESURingInstance* inst, struct io_uring_cqe* cqe)
{
    void* user_data = io_uring_cqe_get_data(cqe);
    ESURingRecvOp* opP;
    ESURingRecvOp** pp;
    int result;
    ErlNifEnv* env;
    ERL_NIF_TERM reason, msg;
    int cancelled;

    __atomic_fetch_add(&gctrl.stat_cqe_processed, 1, __ATOMIC_RELAXED);

    /* Fire-and-forget sends or NULL means no processing needed */
    if (user_data == NULL || user_data == ESURING_FIRE_AND_FORGET) {
        return;
    }

    /* Must be a recvfrom operation */
    opP = (ESURingRecvOp*)user_data;
    result = cqe->res;
    env = opP->env;

    /* Remove from pending list */
    enif_mutex_lock(inst->pending_mtx);
    pp = &inst->pending_recvs;
    while (*pp != NULL) {
        if (*pp == opP) {
            *pp = opP->next;
            break;
        }
        pp = &(*pp)->next;
    }
    cancelled = opP->cancelled;
    enif_mutex_unlock(inst->pending_mtx);

    /* If cancelled, just cleanup without sending message */
    if (cancelled) {
        enif_release_binary(&opP->buf);
        enif_free_env(opP->env);
        enif_free(opP);
        return;
    }

    if (result < 0) {
        /* Error */
        reason = MKA(env, erl_errno_id(-result));
        msg = enif_make_tuple3(env,
                               esock_atom_socket,
                               opP->sockRef,
                               enif_make_tuple2(env,
                                                esock_atom_error,
                                                reason));
    } else {
        /* Success - encode result */
        ERL_NIF_TERM eAddr, eData, eResult;

        esock_encode_sockaddr(env,
                              &opP->fromAddr,
                              opP->msg.msg_namelen,
                              &eAddr);

        if ((size_t)result < opP->buf.size) {
            enif_realloc_binary(&opP->buf, result);
        }
        eData = enif_make_binary(env, &opP->buf);
        eResult = enif_make_tuple2(env, eAddr, eData);

        msg = enif_make_tuple3(env,
                               esock_atom_socket,
                               opP->sockRef,
                               enif_make_tuple2(env,
                                                esock_atom_completion,
                                                enif_make_tuple2(env,
                                                                 opP->recvRef,
                                                                 esock_make_ok2(env, eResult))));
    }

    /* Send message to caller */
    enif_send(NULL, &opP->caller, env, msg);

    /* Cleanup */
    enif_free_env(opP->env);
    enif_free(opP);
}

/* ========================================================================
 * Drain CQE queue (called when SQ is full)
 */

static void
esuring_drain_cqe(ESURingInstance* inst)
{
    struct io_uring_cqe* cqe;
    unsigned int count = 0;

    while (io_uring_peek_cqe(&inst->ring, &cqe) == 0) {
        esuring_process_cqe(inst, cqe);
        io_uring_cqe_seen(&inst->ring, cqe);
        count++;
        if (count >= 64) break;
    }
}

/* ========================================================================
 * sendto - Fire-and-forget UDP send
 */

extern ERL_NIF_TERM
esuring_sendto(ErlNifEnv*       env,
               ESockDescriptor* descP,
               ERL_NIF_TERM     sockRef,
               ERL_NIF_TERM     sendRef,
               ErlNifBinary*    dataP,
               int              flags,
               ESockAddress*    toAddrP,
               SOCKLEN_T        toAddrLen)
{
    ESURingInstance* inst = esuring_get_ring();
    struct io_uring_sqe* sqe;
    ESURingSendEntry* entry;
    unsigned int idx;
    ssize_t ret;

    (void)sockRef;
    (void)sendRef;

    __atomic_fetch_add(&inst->stat_sendto, 1, __ATOMIC_RELAXED);

    if (!IS_OPEN(descP->writeState))
        return esock_make_error_closed(env);

    /* For large packets, use direct syscall */
    if (dataP->size > ESURING_SEND_BUF_SIZE) {
        __atomic_fetch_add(&inst->stat_direct_syscall, 1, __ATOMIC_RELAXED);
        ret = sendto(descP->sock, dataP->data, dataP->size,
                     flags, (struct sockaddr*)toAddrP, toAddrLen);
        if (ret < 0) {
            return esock_make_error_errno(env, errno);
        }
        return esock_atom_ok;
    }

    /* Lock if needed (ring 0 only) - protects circular allocation */
    if (inst->need_mutex)
        enif_mutex_lock(inst->ring_mtx);

    /* Circular allocation - get next buffer slot (protected by mutex for ring 0) */
    idx = inst->send_next_idx++;
    entry = &inst->send_pool[idx % ESURING_SEND_POOL_SIZE];

    /* Copy data to pool buffer */
    memcpy(entry->buf, dataP->data, dataP->size);
    entry->size = dataP->size;
    memcpy(&entry->addr, toAddrP, toAddrLen);
    entry->addrLen = toAddrLen;

    /* Get SQE */
    sqe = io_uring_get_sqe(&inst->ring);
    if (sqe == NULL) {
        /* SQ full - submit and spin with occasional yield for shared SQPOLL */
        int spin;

        io_uring_submit(&inst->ring);
        inst->pending_submits = 0;

        for (spin = 0; spin < 128 && sqe == NULL; spin++) {
            if ((spin & 15) == 0)
                sched_yield();  /* Yield every 16 spins to help SQPOLL thread */
            else
                esuring_cpu_relax();
            sqe = io_uring_get_sqe(&inst->ring);
        }

        if (sqe == NULL) {
            if (inst->need_mutex)
                enif_mutex_unlock(inst->ring_mtx);
            __atomic_fetch_add(&inst->stat_ring_full, 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&inst->stat_direct_syscall, 1, __ATOMIC_RELAXED);
            /* Fall back to direct syscall */
            ret = sendto(descP->sock, dataP->data, dataP->size,
                         flags, (struct sockaddr*)toAddrP, toAddrLen);
            if (ret < 0) {
                return esock_make_error_errno(env, errno);
            }
            return esock_atom_ok;
        }
    }

    /* Prepare sendto operation */
    io_uring_prep_sendto(sqe, descP->sock,
                         entry->buf, entry->size,
                         flags,
                         (struct sockaddr*)&entry->addr, entry->addrLen);

    /* Fire-and-forget: skip CQE on success */
    sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
    io_uring_sqe_set_data(sqe, ESURING_FIRE_AND_FORGET);

    /* Batch submit */
    if (!inst->sqpoll) {
        inst->pending_submits++;
        if (inst->pending_submits >= ESURING_BATCH_SIZE) {
            io_uring_submit(&inst->ring);
            inst->pending_submits = 0;
        }
    }

    if (inst->need_mutex)
        enif_mutex_unlock(inst->ring_mtx);

    return esock_atom_ok;
}

/* ========================================================================
 * sendmsg - Fire-and-forget vectored send
 */

extern ERL_NIF_TERM
esuring_sendmsg(ErlNifEnv*       env,
                ESockDescriptor* descP,
                ERL_NIF_TERM     sockRef,
                ERL_NIF_TERM     sendRef,
                ERL_NIF_TERM     eMsg,
                int              flags,
                ERL_NIF_TERM     eIOV,
                const ESockData* dataP)
{
    ESURingInstance* inst = esuring_get_ring();
    struct io_uring_sqe* sqe;
    ESURingIovecEntry* entry;
    ERL_NIF_TERM eAddr, tail;
    ErlNifIOVec* iovecP = NULL;
    unsigned int i, idx;
    size_t total_size;
    struct msghdr fallback_msg;
    ssize_t ret;

    (void)sockRef;
    (void)sendRef;

    __atomic_fetch_add(&inst->stat_sendmsg, 1, __ATOMIC_RELAXED);

    if (!IS_OPEN(descP->writeState))
        return esock_make_error_closed(env);

    /* Extract iovec from Erlang term */
    if (!enif_inspect_iovec(NULL, dataP->iov_max, eIOV, &tail, &iovecP)) {
        return esock_make_invalid(env, esock_atom_iov);
    }

    if (iovecP->iovcnt == 0 || iovecP->iovcnt > ESURING_IOV_MAX_ENTRIES) {
        if (iovecP != NULL) enif_free_iovec(iovecP);
        return esock_make_invalid(env, esock_atom_iov);
    }

    /* Calculate total data size */
    total_size = 0;
    for (i = 0; i < iovecP->iovcnt; i++) {
        total_size += iovecP->iov[i].iov_len;
    }

    /* If data is too large, fall back to direct syscall */
    if (total_size > ESURING_IOV_BUF_SIZE) {
        ESockAddress fallback_addr;
        SOCKLEN_T fallback_addrLen;

        __atomic_fetch_add(&inst->stat_direct_syscall, 1, __ATOMIC_RELAXED);

        memset(&fallback_msg, 0, sizeof(fallback_msg));
        fallback_msg.msg_iov = iovecP->iov;
        fallback_msg.msg_iovlen = iovecP->iovcnt;

        if (enif_get_map_value(env, eMsg, esock_atom_addr, &eAddr)) {
            if (esock_decode_sockaddr(env, eAddr, &fallback_addr, &fallback_addrLen)) {
                fallback_msg.msg_name = &fallback_addr;
                fallback_msg.msg_namelen = fallback_addrLen;
            }
        }

        ret = sendmsg(descP->sock, &fallback_msg, flags);
        enif_free_iovec(iovecP);

        if (ret < 0) {
            return esock_make_error_errno(env, errno);
        }
        return esock_atom_ok;
    }

    /* Lock if needed (ring 0 only) - protects circular allocation */
    if (inst->need_mutex)
        enif_mutex_lock(inst->ring_mtx);

    /* Circular allocation - get next iovec entry (protected by mutex for ring 0) */
    idx = inst->iov_next_idx++;
    entry = &inst->iov_pool[idx % ESURING_IOV_POOL_SIZE];

    /* Copy iovec data to pool entry buffer */
    entry->buf_used = 0;
    for (i = 0; i < iovecP->iovcnt; i++) {
        memcpy(entry->buf + entry->buf_used,
               iovecP->iov[i].iov_base,
               iovecP->iov[i].iov_len);
        entry->iov[i].iov_base = entry->buf + entry->buf_used;
        entry->iov[i].iov_len = iovecP->iov[i].iov_len;
        entry->buf_used += iovecP->iov[i].iov_len;
    }

    /* Setup msghdr */
    memset(&entry->msg, 0, sizeof(entry->msg));
    entry->msg.msg_iov = entry->iov;
    entry->msg.msg_iovlen = iovecP->iovcnt;

    /* Extract destination address */
    if (enif_get_map_value(env, eMsg, esock_atom_addr, &eAddr)) {
        SOCKLEN_T addrLen;
        if (esock_decode_sockaddr(env, eAddr, &entry->addr, &addrLen)) {
            entry->msg.msg_name = &entry->addr;
            entry->msg.msg_namelen = addrLen;
        }
    }

    enif_free_iovec(iovecP);

    /* Get SQE */
    sqe = io_uring_get_sqe(&inst->ring);
    if (sqe == NULL) {
        /* SQ full - submit and spin with occasional yield for shared SQPOLL */
        int spin;

        io_uring_submit(&inst->ring);
        inst->pending_submits = 0;

        for (spin = 0; spin < 128 && sqe == NULL; spin++) {
            if ((spin & 15) == 0)
                sched_yield();  /* Yield every 16 spins to help SQPOLL thread */
            else
                esuring_cpu_relax();
            sqe = io_uring_get_sqe(&inst->ring);
        }

        if (sqe == NULL) {
            if (inst->need_mutex)
                enif_mutex_unlock(inst->ring_mtx);
            __atomic_fetch_add(&inst->stat_ring_full, 1, __ATOMIC_RELAXED);
            __atomic_fetch_add(&inst->stat_direct_syscall, 1, __ATOMIC_RELAXED);
            ret = sendmsg(descP->sock, &entry->msg, flags);
            if (ret < 0) {
                return esock_make_error_errno(env, errno);
            }
            return esock_atom_ok;
        }
    }

    /* Prepare sendmsg */
    io_uring_prep_sendmsg(sqe, descP->sock, &entry->msg, flags);

    /* Fire-and-forget */
    sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
    io_uring_sqe_set_data(sqe, ESURING_FIRE_AND_FORGET);

    /* Batch submit */
    if (!inst->sqpoll) {
        inst->pending_submits++;
        if (inst->pending_submits >= ESURING_BATCH_SIZE) {
            io_uring_submit(&inst->ring);
            inst->pending_submits = 0;
        }
    }

    if (inst->need_mutex)
        enif_mutex_unlock(inst->ring_mtx);

    return esock_atom_ok;
}

/* ========================================================================
 * recvfrom - Async receive with completion notification
 */

extern ERL_NIF_TERM
esuring_recvfrom(ErlNifEnv*       env,
                 ESockDescriptor* descP,
                 ERL_NIF_TERM     sockRef,
                 ERL_NIF_TERM     recvRef,
                 ssize_t          len,
                 int              flags)
{
    unsigned int ring_idx = esuring_get_ring_idx();
    ESURingInstance* inst = &gctrl.rings[ring_idx];
    struct io_uring_sqe* sqe;
    ESURingRecvOp* opP;
    size_t bufSz;

    __atomic_fetch_add(&inst->stat_recvfrom, 1, __ATOMIC_RELAXED);

    if (!IS_OPEN(descP->readState))
        return esock_make_error_closed(env);

    bufSz = (len > 0) ? (size_t)len : descP->rBufSz;
    if (bufSz == 0) bufSz = 65536;

    /* Allocate operation structure */
    opP = enif_alloc(sizeof(ESURingRecvOp));
    if (opP == NULL)
        return esock_make_error_errno(env, ENOMEM);

    opP->env = enif_alloc_env();

    if (opP->env == NULL) {
        enif_free(opP);
        return esock_make_error_errno(env, ENOMEM);
    }

    enif_self(env, &opP->caller);
    opP->sockRef = enif_make_copy(opP->env, sockRef);
    opP->recvRef = enif_make_copy(opP->env, recvRef);
    opP->cancelled = 0;
    opP->next = NULL;

    /* Allocate receive buffer */
    if (!enif_alloc_binary(bufSz, &opP->buf)) {
        enif_free_env(opP->env);
        enif_free(opP);
        return esock_make_error_errno(env, ENOMEM);
    }

    /* Setup msghdr */
    opP->iov[0].iov_base = opP->buf.data;
    opP->iov[0].iov_len = bufSz;
    memset(&opP->msg, 0, sizeof(opP->msg));
    opP->msg.msg_iov = opP->iov;
    opP->msg.msg_iovlen = 1;
    opP->msg.msg_name = &opP->fromAddr;
    opP->msg.msg_namelen = sizeof(ESockAddress);

    /* Lock if needed */
    if (inst->need_mutex)
        enif_mutex_lock(inst->ring_mtx);

    /* Get SQE */
    sqe = io_uring_get_sqe(&inst->ring);
    if (sqe == NULL) {
        io_uring_submit(&inst->ring);
        esuring_drain_cqe(inst);

        sqe = io_uring_get_sqe(&inst->ring);
        if (sqe == NULL) {
            if (inst->need_mutex)
                enif_mutex_unlock(inst->ring_mtx);
            __atomic_fetch_add(&inst->stat_ring_full, 1, __ATOMIC_RELAXED);
            enif_release_binary(&opP->buf);
            enif_free_env(opP->env);
            enif_free(opP);
            return esock_make_error(env, esock_atom_eagain);
        }
    }

    /* Prepare recvmsg */
    io_uring_prep_recvmsg(sqe, descP->sock, &opP->msg, flags);
    io_uring_sqe_set_data(sqe, opP);

    /* recvfrom needs immediate submit */
    if (!inst->sqpoll) {
        io_uring_submit(&inst->ring);
        inst->pending_submits = 0;
    }

    if (inst->need_mutex)
        enif_mutex_unlock(inst->ring_mtx);

    /* Add to pending list */
    enif_mutex_lock(inst->pending_mtx);
    opP->next = inst->pending_recvs;
    inst->pending_recvs = opP;
    enif_mutex_unlock(inst->pending_mtx);

    /* Return completion reference */
    return esock_make_ok2(env,
                          enif_make_tuple2(env,
                                           esock_atom_completion,
                                           recvRef));
}

/* ========================================================================
 * Cancel operations
 */

extern ERL_NIF_TERM
esuring_cancel_recv(ErlNifEnv*       env,
                    ESockDescriptor* descP,
                    ERL_NIF_TERM     sockRef,
                    ERL_NIF_TERM     opRef)
{
    unsigned int i;
    ESURingRecvOp* opP;
    ESURingRecvOp* found = NULL;
    ESURingInstance* found_inst = NULL;
    struct io_uring_sqe* sqe;

    (void)descP;
    (void)sockRef;

    /* Search all rings for matching operation */
    for (i = 0; i < gctrl.num_rings && found == NULL; i++) {
        ESURingInstance* inst = &gctrl.rings[i];

        enif_mutex_lock(inst->pending_mtx);
        for (opP = inst->pending_recvs; opP != NULL; opP = opP->next) {
            if (enif_compare(opRef, opP->recvRef) == 0) {
                found = opP;
                found_inst = inst;
                found->cancelled = 1;
                break;
            }
        }
        enif_mutex_unlock(inst->pending_mtx);
    }

    if (found == NULL) {
        return esock_atom_ok;
    }

    /* Issue async cancel */
    if (found_inst->need_mutex)
        enif_mutex_lock(found_inst->ring_mtx);

    sqe = io_uring_get_sqe(&found_inst->ring);
    if (sqe != NULL) {
        io_uring_prep_cancel(sqe, found, 0);
        io_uring_sqe_set_data(sqe, NULL);
        if (!found_inst->sqpoll) {
            io_uring_submit(&found_inst->ring);
        }
    }

    if (found_inst->need_mutex)
        enif_mutex_unlock(found_inst->ring_mtx);

    return esock_atom_ok;
}

extern ERL_NIF_TERM
esuring_cancel_send(ErlNifEnv*       env,
                    ESockDescriptor* descP,
                    ERL_NIF_TERM     sockRef,
                    ERL_NIF_TERM     opRef)
{
    (void)env;
    (void)descP;
    (void)sockRef;
    (void)opRef;
    return esock_atom_ok;
}

/* ========================================================================
 * sendmmsg - batch send multiple messages with io_uring
 *
 * This function prepares multiple SQEs in one NIF call, avoiding
 * the per-message NIF call overhead. All messages are submitted
 * as fire-and-forget operations.
 *
 * eMsgs format: list of #{iov => Binary, addr => SockAddr}
 */

extern ERL_NIF_TERM
esuring_sendmmsg(ErlNifEnv*       env,
                 ESockDescriptor* descP,
                 ERL_NIF_TERM     sockRef,
                 ERL_NIF_TERM     sendRef,
                 ERL_NIF_TERM     eMsgs,
                 int              flags,
                 const ESockData* dataP)
{
    ESURingInstance* inst = esuring_get_ring();
    ERL_NIF_TERM head, tail, eAddr, eIOV;
    unsigned int msg_count = 0;
    unsigned int sent_count = 0;

    (void)sockRef;
    (void)sendRef;
    (void)dataP;

    __atomic_fetch_add(&inst->stat_sendmmsg, 1, __ATOMIC_RELAXED);

    if (!IS_OPEN(descP->writeState))
        return esock_make_error_closed(env);

    /* Lock if needed */
    if (inst->need_mutex)
        enif_mutex_lock(inst->ring_mtx);

    /* Process each message in the list */
    tail = eMsgs;
    while (enif_get_list_cell(env, tail, &head, &tail)) {
        ErlNifBinary data;
        ESockAddress toAddr;
        SOCKLEN_T toAddrLen = 0;
        ESURingSendEntry* entry;
        struct io_uring_sqe* sqe;
        unsigned int idx;

        if (msg_count >= ESURING_MMSG_MAX)
            break;

        /* Extract iov (binary data) from message map */
        if (!enif_get_map_value(env, head, esock_atom_iov, &eIOV)) {
            continue;  /* Skip invalid message */
        }
        if (!enif_inspect_iolist_as_binary(env, eIOV, &data)) {
            continue;  /* Skip invalid iov */
        }

        /* Extract addr (optional) */
        if (enif_get_map_value(env, head, esock_atom_addr, &eAddr)) {
            if (!esock_decode_sockaddr(env, eAddr, &toAddr, &toAddrLen)) {
                continue;  /* Skip invalid addr */
            }
        }

        /* Skip if data is too large for pool */
        if (data.size > ESURING_SEND_BUF_SIZE) {
            /* Fall back to direct syscall for large packets */
            ssize_t ret = sendto(descP->sock, data.data, data.size,
                                 flags, (struct sockaddr*)&toAddr, toAddrLen);
            if (ret >= 0) {
                sent_count++;
            }
            __atomic_fetch_add(&inst->stat_direct_syscall, 1, __ATOMIC_RELAXED);
            msg_count++;
            continue;
        }

        /* Allocate from pool */
        idx = inst->send_next_idx++;
        entry = &inst->send_pool[idx % ESURING_SEND_POOL_SIZE];

        /* Copy data to pool buffer */
        memcpy(entry->buf, data.data, data.size);
        entry->size = data.size;
        if (toAddrLen > 0) {
            memcpy(&entry->addr, &toAddr, toAddrLen);
            entry->addrLen = toAddrLen;
        } else {
            entry->addrLen = 0;
        }

        /* Get SQE */
        sqe = io_uring_get_sqe(&inst->ring);
        if (sqe == NULL) {
            /* Ring full - submit and retry */
            io_uring_submit(&inst->ring);
            inst->pending_submits = 0;

            int spin;
            for (spin = 0; spin < 128 && sqe == NULL; spin++) {
                if ((spin & 15) == 0)
                    sched_yield();
                else
                    esuring_cpu_relax();
                sqe = io_uring_get_sqe(&inst->ring);
            }

            if (sqe == NULL) {
                /* Still no SQE - fall back to direct syscall */
                ssize_t ret = sendto(descP->sock, entry->buf, entry->size,
                                     flags, (struct sockaddr*)&entry->addr,
                                     entry->addrLen);
                if (ret >= 0) {
                    sent_count++;
                }
                __atomic_fetch_add(&inst->stat_ring_full, 1, __ATOMIC_RELAXED);
                __atomic_fetch_add(&inst->stat_direct_syscall, 1, __ATOMIC_RELAXED);
                msg_count++;
                continue;
            }
        }

        /* Prepare sendto operation */
        if (entry->addrLen > 0) {
            io_uring_prep_sendto(sqe, descP->sock,
                                 entry->buf, entry->size,
                                 flags,
                                 (struct sockaddr*)&entry->addr, entry->addrLen);
        } else {
            io_uring_prep_send(sqe, descP->sock,
                               entry->buf, entry->size,
                               flags);
        }

        /* Fire-and-forget: skip CQE on success */
        sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
        io_uring_sqe_set_data(sqe, ESURING_FIRE_AND_FORGET);

        sent_count++;
        msg_count++;
        inst->pending_submits++;
    }

    /* Submit all pending SQEs - always submit in sendmmsg to ensure delivery */
    if (inst->pending_submits > 0) {
        io_uring_submit(&inst->ring);
        inst->pending_submits = 0;
    }

    if (inst->need_mutex)
        enif_mutex_unlock(inst->ring_mtx);

    __atomic_fetch_add(&inst->stat_sendmmsg_msgs, sent_count, __ATOMIC_RELAXED);

    return esock_make_ok2(env, enif_make_uint(env, sent_count));
}

#endif /* ESOCK_USE_URING */
