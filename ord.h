/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// skiplist {{{
struct skiplist;

  extern struct skiplist *
skiplist_create(const struct kvmap_mm * const mm);

  extern struct kv *
skiplist_get(struct skiplist * const list, const struct kref * const key, struct kv * const out);

  extern bool
skiplist_probe(struct skiplist * const list, const struct kref * const key);

  extern bool
skiplist_put(struct skiplist * const list, struct kv * const kv);

  extern bool
skipsafe_put(struct skiplist * const list, struct kv * const kv);

  extern bool
skiplist_merge(struct skiplist * const list, const struct kref * const kref,
    kv_merge_func uf, void * const priv);

  extern bool
skipsafe_merge(struct skiplist * const list, const struct kref * const kref,
    kv_merge_func uf, void * const priv);

  extern bool
skiplist_inp(struct skiplist * const list, const struct kref * const key,
    kv_inp_func uf, void * const priv);

  extern bool
skiplist_del(struct skiplist * const list, const struct kref * const key);

  extern void
skiplist_clean(struct skiplist * const list);

  extern void
skiplist_destroy(struct skiplist * const list);

  extern void
skiplist_fprint(struct skiplist * const list, FILE * const out);

struct skiplist_iter;

  extern struct skiplist_iter *
skiplist_iter_create(struct skiplist * const list);

  extern void
skiplist_iter_seek(struct skiplist_iter * const iter, const struct kref * const key);

  extern bool
skiplist_iter_valid(struct skiplist_iter * const iter);

  extern struct kv *
skiplist_iter_peek(struct skiplist_iter * const iter, struct kv * const out);

  extern bool
skiplist_iter_kref(struct skiplist_iter * const iter, struct kref * const kref);

  extern bool
skiplist_iter_kvref(struct skiplist_iter * const iter, struct kvref * const kvref);

  extern void
skiplist_iter_skip1(struct skiplist_iter * const iter);

  extern void
skiplist_iter_skip(struct skiplist_iter * const iter, const u32 nr);

  extern struct kv *
skiplist_iter_next(struct skiplist_iter * const iter, struct kv * const out);

  extern bool
skiplist_iter_inp(struct skiplist_iter * const iter, kv_inp_func uf, void * const priv);

  extern void
skiplist_iter_destroy(struct skiplist_iter * const iter);

extern const struct kvmap_api kvmap_api_skiplist;
extern const struct kvmap_api kvmap_api_skipsafe;
// }}} skiplist

// bptree {{{
struct bptree;

  extern struct bptree *
bptree_create(const struct kvmap_mm * const mm);

  extern struct kv *
bptree_get(struct bptree * const tree, const struct kref * const key, struct kv * const out);

  extern bool
bptree_probe(struct bptree * const tree, const struct kref * const key);

  extern bool
bptree_put(struct bptree * const tree, struct kv * const kv);

  extern bool
bptree_merge(struct bptree * const tree, const struct kref * const kref,
    kv_merge_func uf, void * const priv);

  extern bool
bptree_inp(struct bptree * const tree, const struct kref * const key,
    kv_inp_func uf, void * const priv);

  extern bool
bptree_del(struct bptree * const tree, const struct kref * const key);

  extern void
bptree_clean(struct bptree * const tree);

  extern void
bptree_destroy(struct bptree * const tree);

  extern void
bptree_fprint(struct bptree * const tree, FILE * const out);

struct bptree_iter;

  extern struct bptree_iter *
bptree_iter_create(struct bptree * const tree);

  extern void
bptree_iter_seek(struct bptree_iter * const iter, const struct kref * const key);

  extern void
bptree_iter_seek_le(struct bptree_iter * const iter, const struct kref * const key);

  extern bool
bptree_iter_valid(struct bptree_iter * const iter);

  extern struct kv *
bptree_iter_peek(struct bptree_iter * const iter, struct kv * const out);

  extern bool
bptree_iter_kref(struct bptree_iter * const iter, struct kref * const kref);

  extern bool
bptree_iter_kvref(struct bptree_iter * const iter, struct kvref * const kvref);

  extern struct kv *
bptree_iter_next(struct bptree_iter * const iter, struct kv * const out);

  extern void
bptree_iter_skip1(struct bptree_iter * const iter);

  extern void
bptree_iter_skip(struct bptree_iter * const iter, const u32 nr);

  extern bool
bptree_iter_inp(struct bptree_iter * const iter, kv_inp_func uf, void * const priv);

  extern void
bptree_iter_destroy(struct bptree_iter * const iter);

extern const struct kvmap_api kvmap_api_bptree;
// }}} bptree

// rdb {{{
#ifdef ROCKSDB
struct rdb;
struct rdb_iter;

  extern struct rdb *
rdb_create(const char * const path, const u64 cache_size_mb);

  extern struct kv *
rdb_get(struct rdb * const map, const struct kref * const key, struct kv * const out);

  extern bool
rdb_probe(struct rdb * const map, const struct kref * const key);

  extern bool
rdb_put(struct rdb * const map, struct kv * const kv);

  extern bool
rdb_del(struct rdb * const map, const struct kref * const key);

  extern void
rdb_destroy(struct rdb * const map);

  extern void
rdb_fprint(struct rdb * const map, FILE * const out);

  extern struct rdb_iter *
rdb_iter_create(struct rdb * const map);

  extern void
rdb_iter_seek(struct rdb_iter * const iter, const struct kref * const key);

  extern bool
rdb_iter_valid(struct rdb_iter * const iter);

  extern struct kv *
rdb_iter_peek(struct rdb_iter * const iter, struct kv * const out);

  extern void
rdb_iter_skip1(struct rdb_iter * const iter);

  extern void
rdb_iter_skip(struct rdb_iter * const iter, const u32 nr);

  extern struct kv *
rdb_iter_next(struct rdb_iter * const iter, struct kv * const out);

  extern void
rdb_iter_destroy(struct rdb_iter * const iter);

extern const struct kvmap_api kvmap_api_rdb;
#endif // ROCKSDB
// }}} rdb

// ldb {{{
#ifdef LEVELDB
struct ldb;
struct ldb_iter;

  extern struct ldb *
ldb_create(const char * const path, const u64 cache_size_mb);

  extern struct kv *
ldb_get(struct ldb * const map, const struct kref * const key, struct kv * const out);

  extern bool
ldb_probe(struct ldb * const map, const struct kref * const key);

  extern bool
ldb_put(struct ldb * const map, struct kv * const kv);

  extern bool
ldb_del(struct ldb * const map, const struct kref * const key);

  extern void
ldb_destroy(struct ldb * const map);

  extern void
ldb_fprint(struct ldb * const map, FILE * const out);

  extern struct ldb_iter *
ldb_iter_create(struct ldb * const map);

  extern void
ldb_iter_seek(struct ldb_iter * const iter, const struct kref * const key);

  extern bool
ldb_iter_valid(struct ldb_iter * const iter);

  extern struct kv *
ldb_iter_peek(struct ldb_iter * const iter, struct kv * const out);

  extern void
ldb_iter_skip1(struct ldb_iter * const iter);

  extern void
ldb_iter_skip(struct ldb_iter * const iter, const u32 nr);

  extern struct kv *
ldb_iter_next(struct ldb_iter * const iter, struct kv * const out);

  extern void
ldb_iter_destroy(struct ldb_iter * const iter);

extern const struct kvmap_api kvmap_api_ldb;
#endif // LEVELDB
// }}} ldb

// lmdb {{{
#ifdef LMDB
struct lmdb;
struct lmdb_ref;
struct lmdb_iter;

  extern struct lmdb *
lmdb_open(const char * const path);

  extern struct lmdb_ref *
lmdb_ref(struct lmdb * const db);

  extern struct lmdb *
lmdb_unref(struct lmdb_ref * const ref);

  extern struct lmdb_ref *
lmdbw_ref(struct lmdb * const db);

  extern struct lmdb *
lmdbw_unref(struct lmdb_ref * const ref);

  extern struct kv *
lmdb_get(struct lmdb_ref * const ref, const struct kref * const key, struct kv * const out);

  extern struct kv *
lmdb1_get(struct lmdb * const db, const struct kref * const key, struct kv * const out);

  extern bool
lmdb_probe(struct lmdb_ref * const ref, const struct kref * const key);

  extern bool
lmdb1_probe(struct lmdb * const db, const struct kref * const key);

  extern bool
lmdb_put(struct lmdb_ref * const ref, struct kv * const kv);

  extern bool
lmdb1_put(struct lmdb * const db, struct kv * const kv);

  extern bool
lmdbw_put(struct lmdb_ref * const ref, struct kv * const kv);

  extern bool
lmdb_del(struct lmdb_ref * const ref, const struct kref * const key);

  extern bool
lmdb1_del(struct lmdb * const db, const struct kref * const key);

  extern bool
lmdbw_del(struct lmdb_ref * const ref, const struct kref * const key);

  extern void
lmdb_clean(struct lmdb * const map);

  extern void
lmdb_destroy(struct lmdb * const map);

  extern void
lmdb_fprint(struct lmdb * const map, FILE * const out);

  extern struct lmdb_iter *
lmdb_iter_create(struct lmdb_ref * const ref);

  extern struct lmdb_iter *
lmdb1_iter_create(struct lmdb * const db);

  extern void
lmdb_iter_seek(struct lmdb_iter * const iter, const struct kref * const key);

  extern bool
lmdb_iter_valid(struct lmdb_iter * const iter);

  extern struct kv *
lmdb_iter_peek(struct lmdb_iter * const iter, struct kv * const out);

  extern void
lmdb_iter_skip1(struct lmdb_iter * const iter);

  extern void
lmdb_iter_skip(struct lmdb_iter * const iter, const u32 nr);

  extern struct kv *
lmdb_iter_next(struct lmdb_iter * const iter, struct kv * const out);

  extern void
lmdb_iter_destroy(struct lmdb_iter * const iter);

  extern void
lmdb1_iter_destroy(struct lmdb_iter * const iter);

extern const struct kvmap_api kvmap_api_lmdb;
extern const struct kvmap_api kvmap_api_lmdbw;
extern const struct kvmap_api kvmap_api_lmdb1;
#endif
// }}} lmdb

#ifdef __cplusplus
}
#endif
// vim:fdm=marker
