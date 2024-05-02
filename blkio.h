/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

#include "lib.h"
#if defined(LIBURING)
#include <liburing.h>
#endif // LIBURING

#ifdef __cplusplus
extern "C" {
#endif

// wring {{{
struct wring;

// iosz: fixed write size; must be a multiple of PGSZ
  extern struct wring *
wring_create(const int fd, const u32 iosz, const u32 depth);

  extern void
wring_update_fd(struct wring * const wring, const int fd);

  extern void
wring_destroy(struct wring * const wring);

  extern void *
wring_acquire(struct wring * const wring);

// write part of the buf
  extern void
wring_write_partial(struct wring * const wring, const u64 off,
    void * const buf, const size_t buf_off, const u32 size);

  extern void
wring_write(struct wring * const wring, const u64 off, void * const buf);

// flush the queue and wait for completion
  extern void
wring_flush(struct wring * const wring);

// send an fsync but does not wait for completion
  extern void
wring_fsync(struct wring * const wring);
// }}} wring

// coq {{{

struct coq;
typedef bool (*cowq_func) (void * priv);

  extern struct coq *
coq_create(void);

  extern void
coq_destroy(struct coq * const coq);

// prefer io_uring on Linux; fall back to POSIX AIO
  extern struct coq *
coq_create_auto(const u32 depth);

  extern void
coq_destroy_auto(struct coq * const coq);

  extern u32
corq_enqueue(struct coq * const q, struct co * const co);

  extern u32
cowq_enqueue(struct coq * const q, cowq_func exec, void * const priv);

  extern void
cowq_remove(struct coq * const q, const u32 i);

  extern void
coq_yield(struct coq * const q);

  extern void
coq_idle(struct coq * const q);

  extern void
coq_run(struct coq * const q);

  extern void
coq_install(struct coq * const q);

  extern void
coq_uninstall(void);

  extern struct coq *
coq_current(void);

  extern ssize_t
coq_pread_aio(struct coq * const q, const int fd, void * const buf, const size_t count, const off_t offset);

  extern ssize_t
coq_pwrite_aio(struct coq * const q, const int fd, const void * const buf, const size_t count, const off_t offset);

#if defined(LIBURING)
// io_uring-specific
  extern struct io_uring *
coq_uring_create(const u32 depth);

// use ring==NULL in pread_uring and pwrite_uring
  extern struct coq *
coq_uring_create_pair(const u32 depth);

  extern void
coq_uring_destroy(struct io_uring * const ring);

  extern void
coq_uring_destroy_pair(struct coq * const coq);

  extern ssize_t
coq_pread_uring(struct coq * const q, struct io_uring * const ring,
    const int fd, void * const buf, const size_t count, const u64 offset);

  extern ssize_t
coq_pwrite_uring(struct coq * const q, struct io_uring * const ring,
    const int fd, const void * const buf, const size_t count, const u64 offset);
#endif // LIBURING
// }}} coq

// rcache {{{
  extern struct rcache *
rcache_create(const u64 size_mb, const u32 fd_bits);

  extern void
rcache_set_dump_file(struct rcache * c, char * name);

  extern void
rcache_destroy(struct rcache * const c);

  extern void
rcache_close_lazy(struct rcache * const c, const int fd);

  extern u64
rcache_close_flush(struct rcache * const c);

  extern void
rcache_close(struct rcache * const c, const int fd);

  extern void *
rcache_acquire(struct rcache * const c, const int fd, const u32 pageid);

  extern void
rcache_retain(struct rcache * const c, const void * const buf);

  extern void
rcache_release(struct rcache * const c, const void * const buf);

  extern void
rcache_thread_stat_reset(void);

  extern u64
rcache_thread_stat_reads(void);
// }}} rcache

// rwcache {{{
struct rwcache;

// fd_bits: approximately the number of files to be accessed concurrently
// If there is only one file of fd=3, fd_bits should be at least 2
  extern struct rwcache *
rwcache_create(const u64 size_mb, const u32 fd_bits);

// force write of all dirty pages
  extern void
rwcache_flush_all(struct rwcache * const rwc);

// force write of fd's dirty pages
  extern void
rwcache_flush(struct rwcache * const rwc, const int fd);

// write all dirty pages and close(fd)
  extern void
rwcache_close(struct rwcache * const rwc, const int fd);

  extern void
rwcache_destroy(struct rwcache * const rwc);

// mark page as dirty; must call this before rwcache_release
  extern void
rwcache_dirty(struct rwcache * const rwc, void * const buf);

// sync page if it has been marked dirty
  extern void
rwcache_sync(struct rwcache * const rwc, void * const buf);

// acquire a page for read/write; refcnt++
  extern void *
rwcache_acquire(struct rwcache * const rwc, const int fd, const u32 pno);

// refcnt--
  extern void
rwcache_release(struct rwcache * const rwc, void * const buf);
// }}} rwcache

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
