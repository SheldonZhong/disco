/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include <assert.h> // static_assert
#include "lib.h"
#include "ctypes.h"
#include "kv.h"
#include "ord.h"
// }}} headers

// skiplist {{{
#define SL_MAXH ((32))
struct skipnode {
  struct kv * kv;
  union {
    struct skipnode * ptr;
    au64 a;
  } next[0];
};

struct skippath {
  struct skipnode * vec[SL_MAXH][2]; // left and right
};

struct skiplist {
  mutex lock;
  u64 padding[7];
  struct kvmap_mm mm;
  u64 height;
  struct skipnode n0;
};

  struct skiplist *
skiplist_create(const struct kvmap_mm * const mm)
{
  const size_t sz = sizeof(struct skiplist) + (sizeof(void *) * SL_MAXH);
  struct skiplist * const list = yalloc(sz);
  if (list == NULL)
    return NULL;

  memset(list, 0, sz);
  mutex_init(&(list->lock));
  list->mm = mm ? (*mm) : kvmap_mm_dup;
  list->height = 1;
  return list;
}

  static inline struct skipnode *
skiplist_next(struct skipnode * const node, const u64 h)
{
  return (struct skipnode *)(void *)atomic_load_explicit(&node->next[h].a, MO_ACQUIRE);
}

  static inline void
skiplist_update_next(struct skipnode * const node, const u64 h, struct skipnode * const next)
{
  atomic_store_explicit(&(node->next[h].a), (u64)next, MO_RELEASE);
}

  static inline void
skiplist_lock(struct skiplist * const list)
{
  mutex_lock(&(list->lock));
}

  static inline void
skiplist_unlock(struct skiplist * const list)
{
  mutex_unlock(&(list->lock));
}

// perform a search on skiplist and record the path
// return true for match, false for mismatch
// *out will have the node >= key
// on match, the path could be incomplete (the path is not used unless for del, which will be handled separately)
// on mismatch, at every level of the path, left < key < right (or NULL); a new key should be inserted in between
  static bool
skiplist_search_ge_path(struct skiplist * const list, const struct kref * const key,
    struct skipnode ** const out, struct skippath * const path, u64 h)
{
  debug_assert(h);
  struct skipnode * left = &(list->n0); // leftmost
  struct skipnode * next;
  while ((--h) < SL_MAXH) {
    while ((next = skiplist_next(left, h)) != NULL) {
      const int cmp = kref_kv_compare(key, next->kv);
      if (cmp > 0) { // forward and continue
        left = next;
      } else if (cmp < 0) { // done at this level
        break;
      } else { // match
        *out = next;
        return true;
      }
    }
    path->vec[h][0] = left;
    path->vec[h][1] = next;
  }
  // no match; return the first node > key
  *out = next;
  return false;
}

  static bool
skiplist_search_ge(struct skiplist * const list, const struct kref * const key,
    struct skipnode ** const out)
{
  u64 h = list->height;
  debug_assert(h);
  struct skipnode * left = &(list->n0); // leftmost
  struct skipnode * next;
  while ((--h) < SL_MAXH) {
    while ((next = skiplist_next(left, h)) != NULL) {
      const int cmp = kref_kv_compare(key, next->kv);
      if (cmp > 0) { // forward and continue
        left = next;
      } else if (cmp < 0) { // done at this level
        break;
      } else { // match
        *out = next;
        return true;
      }
    }
  }
  // no match; return the first node > key
  *out = next;
  return false;
}

  struct kv *
skiplist_get(struct skiplist * const list, const struct kref * const key, struct kv * const out)
{
  struct skipnode * node;
  if (skiplist_search_ge(list, key, &node)) {
    debug_assert(node && node->kv);
    return list->mm.out(node->kv, out);
  }
  return NULL;
}

  bool
skiplist_probe(struct skiplist * const list, const struct kref * const key)
{
  struct skipnode * node;
  return skiplist_search_ge(list, key, &node);
}

// generate a random height; if it's higher than hh, fill the path
  static u64
skiplist_random_height(struct skiplist * const list, struct skippath * const path, const u64 hh)
{
  const u64 r = random_u64(); // r can be 0
  // 1 <= height <= 32
  const u64 height = (u64)(__builtin_ctzl(r ? r : 1) >> 1) + 1;
  for (u64 i = hh; i < height; i++) {
    path->vec[i][0] = &(list->n0); // the very beginning
    path->vec[i][1] = NULL; // the very end
  }

  return height;
}

  static bool
skiplist_insert_height(struct skiplist * const list, struct skippath * const path,
    struct kv * const kv, const u64 height)
{
  if (height > list->height)
    list->height = height;

  const u64 nodesize = sizeof(list->n0) + (sizeof(list->n0.next[0]) * height);
  struct skipnode * const node = malloc(nodesize);
  if (!node) { // malloc failed
    list->mm.free(kv, list->mm.priv);
    return false;
  }
  kv->privptr = NULL; // end of chain
  node->kv = kv;
  for (u64 i = 0; i < height; i++) {
    node->next[i].ptr = path->vec[i][1];
    skiplist_update_next(path->vec[i][0], i, node);
  }
  return true;
}

  static bool
skiplist_insert_fix_path(struct skippath * const path, const u64 height, struct kv * const kv)
{
  for (u64 h = 0; h < height; h++) { // must check every level
    struct skipnode * left = path->vec[h][0];
    struct skipnode * right = left->next[h].ptr;

    if (likely(right == path->vec[h][1]))
      continue;

    debug_assert(right); // insertions only; won't disappear

    do {
      const int cmp = kv_compare(kv, right->kv);
      if (cmp < 0) { // right is ok
        break;
      } else if (cmp > 0) { // forward path[h]
        left = right;
        right = left->next[h].ptr;
      } else {
        kv->privptr = right->kv;
        right->kv = kv;
        // insertion is already done
        return true;
      }
    } while (right);
    path->vec[h][0] = left;
    path->vec[h][1] = right;
  }
  // should continue insert
  return false;
}

  static bool
skiplist_insert_helper(struct skiplist * const list, struct skippath * const path,
    const u64 hh, struct kv * const kv, const bool safe)
{
  const u64 height = skiplist_random_height(list, path, hh);

  if (safe) { // other writers may insert keys to the path
    skiplist_lock(list);
    if (skiplist_insert_fix_path(path, height, kv)) {
      skiplist_unlock(list);
      return true;
    }
  }

  const bool r = skiplist_insert_height(list, path, kv, height);

  if (safe)
    skiplist_unlock(list);
  return r;
}

  static bool
skiplist_put_helper(struct skiplist * const list, struct kv * const kv, const bool safe)
{
  struct kv * const newkv = list->mm.in(kv, list->mm.priv);
  if (!newkv)
    return false;

  struct kref kref;
  kref_ref_kv(&kref, kv);
  struct skipnode * node;
  struct skippath path;
  const u64 hh = list->height;
  const bool r = skiplist_search_ge_path(list, &kref, &node, &path, hh);
  if (r) { // replace
    if (safe) {
      skiplist_lock(list);
      newkv->privptr = node->kv;
      node->kv = newkv;
      skiplist_unlock(list);
    } else {
      list->mm.free(node->kv, list->mm.priv);
      newkv->privptr = NULL;
      node->kv = newkv;
    }
    return true;
  }

  return skiplist_insert_helper(list, &path, hh, newkv, safe);
}

  bool
skiplist_put(struct skiplist * const list, struct kv * const kv)
{
  return skiplist_put_helper(list, kv, false);
}

  bool
skipsafe_put(struct skiplist * const list, struct kv * const kv)
{
  return skiplist_put_helper(list, kv, true);
}

  static bool
skiplist_merge_helper(struct skiplist * const list, const struct kref * const kref,
    kv_merge_func uf, void * const priv, const bool safe)
{
  struct skipnode * node;
  struct skippath path;
  const u64 hh = list->height;

  const bool r = skiplist_search_ge_path(list, kref, &node, &path, hh);

  if (r) {
    if (safe) {
      skiplist_lock(list);
      struct kv * const old = node->kv;
      struct kv * const kv = uf(old, priv);
      if ((kv != old) && (kv != NULL)) { // replace
        struct kv * const newkv = list->mm.in(kv, list->mm.priv);
        if (!newkv) {
          skiplist_unlock(list);
          return false;
        }
        newkv->privptr = old;
        node->kv = newkv;
      }
      skiplist_unlock(list);
    } else { // unsafe
      struct kv * const old = node->kv;
      struct kv * const kv = uf(old, priv);
      if (kv != old) { // replace
        struct kv * const newkv = list->mm.in(kv, list->mm.priv);
        if (!newkv)
          return false;

        list->mm.free(old, list->mm.priv);
        newkv->privptr = NULL;
        node->kv = newkv;
      }
    }
    return true;
  }

  struct kv * const kv = uf(NULL, priv);
  if (!kv) // do nothing
    return true;

  struct kv * const newkv = list->mm.in(kv, list->mm.priv);
  if (!newkv)
    return false;

  return skiplist_insert_helper(list, &path, hh, newkv, safe);
}

  bool
skiplist_merge(struct skiplist * const list, const struct kref * const kref,
    kv_merge_func uf, void * const priv)
{
  return skiplist_merge_helper(list, kref, uf, priv, false);
}

  bool
skipsafe_merge(struct skiplist * const list, const struct kref * const kref,
    kv_merge_func uf, void * const priv)
{
  return skiplist_merge_helper(list, kref, uf, priv, true);
}

  bool
skiplist_inp(struct skiplist * const list, const struct kref * const key,
    kv_inp_func uf, void * const priv)
{
  struct skipnode * node;
  const bool r = skiplist_search_ge(list, key, &node);
  uf(r ? node->kv : NULL, priv);
  return r;
}

// return the previous node if ret->next matches the key
  static u64
skiplist_search_del_prev(struct skiplist * const list, const struct kref * const key,
    struct skipnode ** const prev)
{
  debug_assert(list->height);
  u64 h = list->height;
  struct skipnode * left = &(list->n0); // leftmost
  struct skipnode * next;
  while ((--h) < SL_MAXH) {
    while ((next = skiplist_next(left, h)) != NULL) {
      const int cmp = kref_kv_compare(key, next->kv);
      if (cmp > 0) { // forward and continue
        left = next;
      } else if (cmp < 0) { // done at this level
        break;
      } else { // match
        *prev = left;
        return h;
      }
    }
  }
  return SL_MAXH;
}

// for unsafe skiplist only
  bool
skiplist_del(struct skiplist * const list, const struct kref * const key)
{
  struct skipnode * prev = NULL;
  u64 h = skiplist_search_del_prev(list, key, &prev);
  if (h == SL_MAXH)
    return false;

  struct skipnode * const victim = skiplist_next(prev, h);
  prev->next[h].ptr = victim->next[h].ptr;

  while ((--h) < SL_MAXH) {
    while (prev->next[h].ptr != victim)
      prev = prev->next[h].ptr;
    prev->next[h].ptr = victim->next[h].ptr;
  }

  list->mm.free(victim->kv, list->mm.priv);
  free(victim);
  return true;
}

  void
skiplist_clean(struct skiplist * const list)
{
  struct skipnode * iter = list->n0.next[0].ptr;
  while (iter) {
    struct skipnode * const next = iter->next[0].ptr;
    struct kv * kviter = iter->kv;
    while (kviter) { // free the chain
      struct kv * tmp = kviter->privptr;
      list->mm.free(kviter, list->mm.priv);
      kviter = tmp;
    }
    free(iter);
    iter = next;
  }
  for (u64 i = 0; i < SL_MAXH; i++)
    list->n0.next[i].ptr = NULL;
}

  void
skiplist_destroy(struct skiplist * const list)
{
  skiplist_clean(list);
  free(list);
}

  void
skiplist_fprint(struct skiplist * const list, FILE * const out)
{
  u64 hs[SL_MAXH] = {};
  u32 costs[SL_MAXH];
  struct skipnode * nexts[SL_MAXH+1];
  const u64 hh = list->height;
  debug_assert(hh && hh < SL_MAXH);
  for (u64 i = 0; i < hh; i++) {
    nexts[i] = skiplist_next(&list->n0, i);
    costs[i] = 1u;
  }
  nexts[hh] = NULL;

  struct skipnode * iter = nexts[0]; // the first item
  u64 totcost = 0;
  u64 totkv = 0;
  while (iter) {
    u64 h = 0;
    while ((h+1) < SL_MAXH && nexts[h+1] == iter) {
      costs[h] = 1;
      nexts[h] = skiplist_next(iter, h);
      h++;
    }
    nexts[h] = skiplist_next(iter, h);
    hs[h]++;

    u32 cost = 0;
    for (u64 i = h; i < hh; i++)
      cost += costs[i];

    // uncomment to print
    //fprintf(out, "h=%2lu c=%3u", h, cost);
    //kv_print(iter->kv, "sn", out);

    costs[h]++;
    iter = skiplist_next(iter, 0);
    totcost += cost;
    totkv++;
  }

  const double avgcost = (double)totcost / (double)totkv;
  fprintf(out, "SKIPLIST count %lu height %lu avgcost %.3lf\n", totkv, hh, avgcost);
  for (u64 i = 0; i < hh; i += 4) {
    fprintf(out, "SKIPLIST H[%lu] %lu H[%lu] %lu H[%lu] %lu H[%lu] %lu\n",
        i, hs[i], i+1, hs[i+1], i+2, hs[i+2], i+3, hs[i+3]);
  }
}

struct skiplist_iter {
  struct skipnode * curr;
  struct skiplist * list;
};

  struct skiplist_iter *
skiplist_iter_create(struct skiplist * const list)
{
  struct skiplist_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;

  iter->curr = NULL; // invalid
  iter->list = list;
  return iter;
}

  void
skiplist_iter_seek(struct skiplist_iter * const iter, const struct kref * const key)
{
  struct skiplist * list = iter->list;
  skiplist_search_ge(list, key, &iter->curr);
}

  bool
skiplist_iter_valid(struct skiplist_iter * const iter)
{
  return iter->curr != NULL;
}

  struct kv *
skiplist_iter_peek(struct skiplist_iter * const iter, struct kv * const out)
{
  if (!skiplist_iter_valid(iter))
    return NULL;
  struct kv * const curr = iter->curr->kv;
  struct kv * const ret = iter->list->mm.out(curr, out);
  return ret;
}

  bool
skiplist_iter_kref(struct skiplist_iter * const iter, struct kref * const kref)
{
  if (!skiplist_iter_valid(iter))
    return false;
  kref_ref_kv(kref, iter->curr->kv);
  return true;
}

  bool
skiplist_iter_kvref(struct skiplist_iter * const iter, struct kvref * const kvref)
{
  if (!skiplist_iter_valid(iter))
    return false;
  kvref_ref_kv(kvref, iter->curr->kv);
  return true;
}

  void
skiplist_iter_skip1(struct skiplist_iter * const iter)
{
  if (skiplist_iter_valid(iter))
    iter->curr = skiplist_next(iter->curr, 0);
}

  void
skiplist_iter_skip(struct skiplist_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!skiplist_iter_valid(iter))
      return;
    iter->curr = skiplist_next(iter->curr, 0);
  }
}

  struct kv *
skiplist_iter_next(struct skiplist_iter * const iter, struct kv * const out)
{
  struct kv * const ret = skiplist_iter_peek(iter, out);
  skiplist_iter_skip1(iter);
  return ret;
}

  bool
skiplist_iter_inp(struct skiplist_iter * const iter, kv_inp_func uf, void * const priv)
{
  struct kv * const kv = iter->curr ? iter->curr->kv : NULL;
  uf(kv, priv); // call uf even if (kv == NULL)
  return kv != NULL;
}

  void
skiplist_iter_destroy(struct skiplist_iter * const iter)
{
  free(iter);
}

const struct kvmap_api kvmap_api_skiplist = {
  .ordered = true,
  .unique = true,
  .put = (void *)skiplist_put,
  .get = (void *)skiplist_get,
  .probe = (void *)skiplist_probe,
  .del = (void *)skiplist_del,
  .inpr = (void *)skiplist_inp,
  .inpw = (void *)skiplist_inp,
  .merge = (void *)skiplist_merge,
  .iter_create = (void *)skiplist_iter_create,
  .iter_seek = (void *)skiplist_iter_seek,
  .iter_valid = (void *)skiplist_iter_valid,
  .iter_peek = (void *)skiplist_iter_peek,
  .iter_kref = (void *)skiplist_iter_kref,
  .iter_kvref = (void *)skiplist_iter_kvref,
  .iter_skip1 = (void *)skiplist_iter_skip1,
  .iter_skip = (void *)skiplist_iter_skip,
  .iter_next = (void *)skiplist_iter_next,
  .iter_inp = (void *)skiplist_iter_inp,
  .iter_destroy = (void *)skiplist_iter_destroy,
  .clean = (void *)skiplist_clean,
  .destroy = (void *)skiplist_destroy,
  .fprint = (void *)skiplist_fprint,
};

const struct kvmap_api kvmap_api_skipsafe = {
  .ordered = true,
  .unique = true,
  .irefsafe = true,
  .put = (void *)skipsafe_put,
  .get = (void *)skiplist_get,
  .probe = (void *)skiplist_probe,
  .del = NULL,
  .inpr = (void *)skiplist_inp,
  .inpw = (void *)skiplist_inp,
  .merge = (void *)skipsafe_merge,
  .iter_create = (void *)skiplist_iter_create,
  .iter_seek = (void *)skiplist_iter_seek,
  .iter_valid = (void *)skiplist_iter_valid,
  .iter_peek = (void *)skiplist_iter_peek,
  .iter_kref = (void *)skiplist_iter_kref,
  .iter_kvref = (void *)skiplist_iter_kvref,
  .iter_skip1 = (void *)skiplist_iter_skip1,
  .iter_skip = (void *)skiplist_iter_skip,
  .iter_next = (void *)skiplist_iter_next,
  .iter_inp = (void *)skiplist_iter_inp,
  .iter_destroy = (void *)skiplist_iter_destroy,
  .clean = (void *)skiplist_clean,
  .destroy = (void *)skiplist_destroy,
  .fprint = (void *)skiplist_fprint,
};

  static void *
skiplist_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  if (strcmp(name, "skiplist") && strcmp(name, "skipsafe"))
    return NULL;
  (void)args;
  return skiplist_create(mm);
}

__attribute__((constructor))
  static void
skiplist_kvmap_api_init(void)
{
  kvmap_api_register(0, "skiplist", "", skiplist_kvmap_api_create, &kvmap_api_skiplist);
  kvmap_api_register(0, "skipsafe", "", skiplist_kvmap_api_create, &kvmap_api_skipsafe);
}
// }}} skiplist

// bptree {{{
#define BPTREE_META_FO ((64))
#define BPTREE_LEAF_FO ((BPTREE_META_FO * 2))
#define BPTREE_CMP_MATCH ((1u << 31))

// struct {{{
struct bpnode {
  bool leaf; // is_leaf
  u32 nr; // number of keys

  // links to the siblings at the same level
  struct bpnode * prev;
  struct bpnode * next;

  union {
    // meta node
    struct {
      struct kv * key[BPTREE_META_FO];
      struct bpnode * sub[BPTREE_META_FO];
    };
    // leaf node
    struct kv * kvs[BPTREE_LEAF_FO];
  };
};

static_assert(sizeof(struct bpnode) < PGSZ, "bpnode size");

struct bptree {
  u64 depth; // optional
  struct bpnode * root;
  struct slab * slab;
  struct kvmap_mm mm;
};
// }}} struct

// helpers {{{
  static inline struct bpnode *
bptree_alloc_node(struct bptree * const tree, const bool leaf)
{
  struct bpnode * const node = slab_alloc_unsafe(tree->slab);
  node->leaf = leaf;
  node->nr = 0;
  node->prev = NULL;
  node->next = NULL;
  // the pointers/keys are uninitialized
  return node;
}

  static u32
bptree_leaf_search_ge(struct bpnode * const node, const struct kref * const key)
{
  debug_assert(node && node->leaf);
  u32 l = 0;
  u32 r = node->nr;
  while ((l + 2) < r) {
    const u32 m = (l + r) >> 1;
    struct kv * const curr = node->kvs[m];
    cpu_prefetch0(curr);
    cpu_prefetch0(node->kvs+((l+m)>>1));
    cpu_prefetch0(node->kvs+((m+1+r)>>1));
    const int cmp = kref_kv_compare(key, curr);
    if (cmp < 0)
      r = m;
    else if (cmp > 0)
      l = m + 1;
    else
      return m | BPTREE_CMP_MATCH;
  }
  while (l < r) {
    const u32 m = (l + r) >> 1;
    struct kv * const curr = node->kvs[m];
    const int cmp = kref_kv_compare(key, curr);
    if (cmp < 0)
      r = m;
    else if (cmp > 0)
      l = m + 1;
    else
      return m | BPTREE_CMP_MATCH;
  }
  return l;
}

// for insert
  static u32
bptree_meta_search_ge(struct bpnode * const node, const struct kv * const key)
{
  debug_assert(node && (!node->leaf));
  debug_assert(node->nr); // nr > 0
  u32 l = 0;
  u32 r = node->nr;
  while ((l + 2) < r) {
    const u32 m = (l + r) >> 1;
    struct kv * const curr = node->key[m];
    cpu_prefetch0(curr);
    cpu_prefetch0(node->key+((l+m)>>1));
    cpu_prefetch0(node->key+((m+1+r)>>1));
    const int cmp = kv_compare(key, curr);
    if (cmp < 0)
      r = m; // m always > 0
    else if (cmp > 0)
      l = m + 1;
    else
      return m;
  }
  while (l < r) {
    const u32 m = (l + r) >> 1;
    struct kv * const curr = node->key[m];
    const int cmp = kv_compare(key, curr);
    if (cmp < 0)
      r = m; // m always > 0
    else if (cmp > 0)
      l = m + 1;
    else
      return m;
  }
  return l;
}

// for lookup
  static u32
bptree_meta_search_le(struct bpnode * const node, const struct kref * const key)
{
  debug_assert(node->leaf == false);
  debug_assert(node->nr);
  u32 l = 0;
  u32 r = node->nr;
  while ((l + 3) < r) {
    const u32 m = (l + r) >> 1;
    struct kv * const curr = node->key[m];
    cpu_prefetch0(curr);
    cpu_prefetch0(node->key+((l+m)>>1));
    cpu_prefetch0(node->key+((m+r)>>1));
    const int cmp = kref_kv_compare(key, curr);
    if (cmp < 0)
      r = m; // m always > 0
    else if (cmp > 0)
      l = m;
    else
      return m;
  }
  while ((l + 1) < r) {
    const u32 m = (l + r) >> 1;
    struct kv * const curr = node->key[m];
    const int cmp = kref_kv_compare(key, curr);
    if (cmp < 0)
      r = m; // m always > 0
    else if (cmp > 0)
      l = m;
    else
      return m;
  }
  return l;
}

  static struct bpnode *
bptree_down_leaf(struct bptree * const tree, const struct kref * const key)
{
  struct bpnode * node = tree->root;
  while (node->leaf == false) {
    const u32 subidx = bptree_meta_search_le(node, key);
    node = node->sub[subidx];
  }
  return node;
}
// }}} helpers

// create {{{
  struct bptree *
bptree_create(const struct kvmap_mm * const mm)
{
  struct bptree * const tree = malloc(sizeof(*tree));
  if (tree == NULL)
    return NULL;
  tree->mm = mm ? (*mm) : kvmap_mm_dup;
  tree->slab = slab_create(sizeof(struct bpnode), 1lu << 21);
  if (tree->slab == NULL) {
    free(tree);
    return NULL;
  }
  // the new root is leaf
  struct bpnode * const root = bptree_alloc_node(tree, true);
  if (root == NULL) {
    slab_destroy(tree->slab);
    free(tree);
    return NULL;
  }
  tree->root = root;
  tree->depth = 0;
  return tree;
}
// }}} create

// read-only {{{
  struct kv *
bptree_get(struct bptree * const tree, const struct kref * const key, struct kv * const out)
{
  struct bpnode * const leaf = bptree_down_leaf(tree, key);
  debug_assert(leaf->leaf);

  const u32 idx = bptree_leaf_search_ge(leaf, key);
  if (idx & BPTREE_CMP_MATCH) { // update
    const u32 idxm = idx & ~BPTREE_CMP_MATCH;
    struct kv * const kv = leaf->kvs[idxm];
    struct kv * const ret = tree->mm.out(kv, out);
    return ret;
  }
  return NULL;
}

  bool
bptree_probe(struct bptree * const tree, const struct kref * const key)
{
  struct bpnode * const leaf = bptree_down_leaf(tree, key);
  debug_assert(leaf->leaf);

  const u32 idx = bptree_leaf_search_ge(leaf, key);
  return (idx & BPTREE_CMP_MATCH) != 0;
}

  bool
bptree_inp(struct bptree * const tree, const struct kref * const key,
    kv_inp_func uf, void * const priv)
{
  struct bpnode * const leaf = bptree_down_leaf(tree, key);
  debug_assert(leaf->leaf);

  const u32 idx = bptree_leaf_search_ge(leaf, key);
  if (idx & BPTREE_CMP_MATCH) { // update
    const u32 idxm = idx & ~BPTREE_CMP_MATCH;
    struct kv * const kv = leaf->kvs[idxm];
    uf(kv, priv);
    return true;
  } else {
    uf(NULL, priv);
    return false;
  }
}
// }}} read-only

// balance {{{
  static bool
bptree_leaf_balance(struct bpnode * const left, struct bpnode * const right)
{
  debug_assert(left->leaf && right->leaf);
  const u32 nr_r = (left->nr + right->nr) >> 1;
  const u32 nr_l = (left->nr + right->nr) - nr_r;
  if (nr_l == left->nr) { // unchanged
    return false;
  } else if (nr_l < left->nr) { // shift right
    const u32 nmove = nr_r - right->nr;
    memmove(&(right->kvs[nmove]), &(right->kvs[0]), sizeof(right->kvs[0]) * right->nr);
    memmove(&(right->kvs[0]), &(left->kvs[nr_l]), sizeof(right->kvs[0]) * nmove);
  } else { // shift left
    const u32 nmove = nr_l - left->nr;
    memmove(&(left->kvs[left->nr]), &(right->kvs[0]), sizeof(right->kvs[0]) * nmove);
    memmove(&(right->kvs[0]), &(right->kvs[nmove]), sizeof(right->kvs[0]) * nr_r);
  }
  left->nr = nr_l;
  right->nr = nr_r;
  return true;
}

  static bool
bptree_meta_rebalance(struct bpnode * const left, struct bpnode * const right)
{
  debug_assert((left->leaf == false) && (right->leaf == false));
  const u32 nr_r = (left->nr + right->nr) >> 1;
  const u32 nr_l = (left->nr + right->nr) - nr_r;
  if (nr_l == left->nr) {
    return false;
  } else if (nr_l < left->nr) { // shift right
    const u32 nmove = nr_r - right->nr;
    memmove(&(right->key[nmove]), &(right->key[0]), sizeof(right->key[0]) * right->nr);
    memmove(&(right->sub[nmove]), &(right->sub[0]), sizeof(right->sub[0]) * right->nr);
    memmove(&(right->key[0]), &(left->key[nr_l]), sizeof(right->key[0]) * nmove);
    memmove(&(right->sub[0]), &(left->sub[nr_l]), sizeof(right->sub[0]) * nmove);
  } else { // shift left
    const u32 nmove = nr_l - left->nr;
    memmove(&(left->key[left->nr]), &(right->key[0]), sizeof(right->key[0]) * nmove);
    memmove(&(left->sub[left->nr]), &(right->sub[0]), sizeof(right->sub[0]) * nmove);
    memmove(&(right->key[0]), &(right->key[nmove]), sizeof(right->key[0]) * nr_r);
    memmove(&(right->sub[0]), &(right->sub[nmove]), sizeof(right->sub[0]) * nr_r);
  }
  left->nr = nr_l;
  right->nr = nr_r;
  return true;
}
// }}} balance

// put {{{
  static void
bptree_leaf_insert(struct bpnode * const leaf, struct kv * const kv, const u32 idx)
{
  debug_assert(leaf->nr < BPTREE_LEAF_FO);
  const u32 nmove = leaf->nr - idx;
  memmove(&(leaf->kvs[idx+1]), &(leaf->kvs[idx]), sizeof(leaf->kvs[0]) * nmove);
  leaf->kvs[idx] = kv;
  leaf->nr++;
}

// return the new (right) sibliing of node if split
  static struct bpnode *
bptree_leaf_put(struct bptree * const tree, struct bpnode * const leaf,
    const struct kref * const kref, struct kv * const kv)
{
  debug_assert(leaf->leaf);
  const u32 idx = bptree_leaf_search_ge(leaf, kref);
  if (idx & BPTREE_CMP_MATCH) { // update
    const u32 idxm = idx & ~BPTREE_CMP_MATCH;
    struct kv * const victim = (typeof(victim))(leaf->kvs[idxm]);
    if (tree->mm.free)
      tree->mm.free(victim, tree->mm.priv);
    leaf->kvs[idxm] = kv;
    return NULL; // no split
  } else if (leaf->nr < BPTREE_LEAF_FO) { // insert
    bptree_leaf_insert(leaf, kv, idx);
    return NULL;
  }

  // leaf is full; split leaf
  struct bpnode * const newleaf = bptree_alloc_node(tree, true);
  bptree_leaf_balance(leaf, newleaf); // half-half
  // link
  newleaf->next = leaf->next;
  newleaf->prev = leaf;
  leaf->next = newleaf;
  if (newleaf->next)
    newleaf->next->prev = newleaf;
  // insert
  struct bpnode * const down = (kv_compare(kv, newleaf->kvs[0]) < 0) ? leaf : newleaf;
  bptree_leaf_insert(down, kv, bptree_leaf_search_ge(down, kref));
  // the caller will insert newleaf into the meta node
  // the parent node may recursively split
  return newleaf;
}

  static void
bptree_meta_insert(struct bpnode * const parent, struct bpnode * const newchild)
{
  debug_assert(parent->nr < BPTREE_META_FO);
  const struct kv * const anchor0 = newchild->leaf ? newchild->kvs[0] : newchild->key[0];
  struct kv * const anchor = kv_dup_key(anchor0);
  const u32 idx = bptree_meta_search_ge(parent, anchor);
  const u32 nmove = parent->nr - idx;
  memmove(&(parent->key[idx+1]), &(parent->key[idx]), sizeof(parent->key[0]) * nmove);
  parent->key[idx] = anchor;
  memmove(&(parent->sub[idx+1]), &(parent->sub[idx]), sizeof(parent->sub[0]) * nmove);
  parent->sub[idx] = newchild;
  parent->nr++;
}

// return the new (right) sibliing of node if split
  static struct bpnode *
bptree_put_rec(struct bptree * const tree, struct bpnode * const node,
    const struct kref * const kref, struct kv * const new)
{
  // on leaf
  if (node->leaf)
    return bptree_leaf_put(tree, node, kref, new);

  // internal
  const u32 id0 = bptree_meta_search_le(node, kref);
  struct bpnode * const newchild = bptree_put_rec(tree, node->sub[id0], kref, new);
  if (newchild == NULL)
    return NULL;

  // child split
  if (node->nr < BPTREE_META_FO) {
    bptree_meta_insert(node, newchild);
    return NULL;
  }

  // child split and this node is full; split
  struct bpnode * const right = bptree_alloc_node(tree, false);
  (void)bptree_meta_rebalance(node, right); // half-half

  struct bpnode * const down = kv_compare(new, right->key[0]) < 0 ? node : right;
  bptree_meta_insert(down, newchild);
  return right;
}

  static void
bptree_lift_root(struct bptree * const tree, struct bpnode * const newchild)
{
  struct bpnode * const newroot = bptree_alloc_node(tree, false);
  newroot->nr = 2;
  newroot->key[0] = kv_dup_key(kv_null());
  debug_assert(newroot->key[0]);
  newroot->sub[0] = tree->root;
  newroot->key[1] = kv_dup_key(newchild->leaf ? newchild->kvs[0] : newchild->key[0]);
  newroot->sub[1] = newchild;
  tree->root = newroot;
  tree->depth++;
}

  bool
bptree_put(struct bptree * const tree, struct kv * const kv)
{
  struct kv * const new = tree->mm.in(kv, tree->mm.priv);
  if (new == NULL)
    return false;

  const struct kref kref = kv_kref(new);
  struct bpnode * const newchild = bptree_put_rec(tree, tree->root, &kref, new);
  // root just split; depth +1
  if (newchild)
    bptree_lift_root(tree, newchild);
  return true;
}

  static bool
bptree_leaf_merge(struct bptree * const tree, struct bpnode * const leaf,
    const struct kref * const kref, struct bpnode ** pnewleaf, kv_merge_func uf, void * const priv)
{
  debug_assert(leaf->leaf);
  const u32 idx = bptree_leaf_search_ge(leaf, kref);
  if (idx & BPTREE_CMP_MATCH) { // update
    const u32 idxm = idx & ~BPTREE_CMP_MATCH;
    struct kv * const curr = leaf->kvs[idxm];
    struct kv * const kv = uf(curr, priv);
    if ((kv != curr) && (kv != NULL)) {
      struct kv * const new = tree->mm.in(kv, tree->mm.priv);
      if (!new)
        return false;
      tree->mm.free(curr, tree->mm.priv);
      leaf->kvs[idxm] = new;
    }
    return true; // done without split
  }

  // insert
  struct kv * const kv = uf(NULL, priv);
  if (!kv) // do nothing
    return true;

  struct kv * const new = tree->mm.in(kv, tree->mm.priv);
  if (!new)
    return false;

  if (leaf->nr < BPTREE_LEAF_FO) { // insert
    bptree_leaf_insert(leaf, new, idx);
    return true;
  }

  // leaf is full; split leaf
  struct bpnode * const newleaf = bptree_alloc_node(tree, true);
  if (!newleaf) {
    tree->mm.free(new, tree->mm.priv);
    return false;
  }
  bptree_leaf_balance(leaf, newleaf); // half-half
  // link
  newleaf->next = leaf->next;
  newleaf->prev = leaf;
  leaf->next = newleaf;
  if (newleaf->next)
    newleaf->next->prev = newleaf;
  // insert
  struct bpnode * const down = (kv_compare(kv, newleaf->kvs[0]) < 0) ? leaf : newleaf;
  bptree_leaf_insert(down, new, bptree_leaf_search_ge(down, kref));
  // the caller will insert newleaf into the meta node
  // the parent node may recursively split
  *pnewleaf = newleaf;
  return true;
}

// return the new (right) sibliing of node if split
  static bool
bptree_merge_rec(struct bptree * const tree, struct bpnode * const node,
    const struct kref * const kref, struct bpnode ** pnewnode, kv_merge_func uf, void * const priv)
{
  // on leaf
  if (node->leaf) {
    return bptree_leaf_merge(tree, node, kref, pnewnode, uf, priv);
  }

  // internal
  const u32 id0 = bptree_meta_search_le(node, kref);
  struct bpnode * newchild = NULL;
  const bool r = bptree_merge_rec(tree, node->sub[id0], kref, &newchild, uf, priv);
  if (!newchild)
    return r;

  // child split
  if (node->nr < BPTREE_META_FO) {
    bptree_meta_insert(node, newchild);
    return true;
  }

  // child split and this node is full; split
  struct bpnode * const right = bptree_alloc_node(tree, false);
  // TODO: right could fail
  debug_assert(right);
  (void)bptree_meta_rebalance(node, right); // half-half

  struct bpnode * const down = kref_kv_compare(kref, right->key[0]) < 0 ? node : right;
  bptree_meta_insert(down, newchild);
  *pnewnode = right;
  return true;
}

  bool
bptree_merge(struct bptree * const tree, const struct kref * const kref,
    kv_merge_func uf, void * const priv)
{
  struct bpnode * newnode = NULL;
  const bool r = bptree_merge_rec(tree, tree->root, kref, &newnode, uf, priv);
  if (r && newnode)
    bptree_lift_root(tree, newnode);
  return r;
}
// }}} put

// del {{{
  static bool
bptree_leaf_del(struct bptree * const tree, struct bpnode * const leaf,
    const struct kref * const key)
{
  debug_assert(leaf->leaf);

  const u32 idx = bptree_leaf_search_ge(leaf, key);
  if (idx & BPTREE_CMP_MATCH) { // found
    const u32 idxm = idx & (~BPTREE_CMP_MATCH);
    struct kv * const victim = (typeof(victim))(leaf->kvs[idxm]);
    if (tree->mm.free)
      tree->mm.free(victim, tree->mm.priv);
    const u32 nmove = leaf->nr - idxm - 1;
    memmove(&(leaf->kvs[idxm]), &(leaf->kvs[idxm+1]), sizeof(leaf->kvs[0]) * nmove);
    leaf->nr--;
    return true;
  }
  return false;
}

  static void
bptree_meta_del(struct bptree * const tree, struct bpnode * const node, const u32 idx)
{
  debug_assert(node->leaf == false);
  slab_free_unsafe(tree->slab, node->sub[idx]);
  free(node->key[idx]);
  const u32 nmove = node->nr - idx - 1;
  memmove(&(node->key[idx]), &(node->key[idx+1]), sizeof(node->key[0]) * nmove);
  memmove(&(node->sub[idx]), &(node->sub[idx+1]), sizeof(node->sub[0]) * nmove);
  node->nr--;
}

// move everything from right to left
  static void
bptree_leaf_merge2(struct bpnode * const left, struct bpnode * const right)
{
  debug_assert(left->leaf && right->leaf);
  debug_assert((left->nr + right->nr) <= BPTREE_LEAF_FO);
  memcpy(&(left->kvs[left->nr]), &(right->kvs[0]), sizeof(right->kvs[0]) * right->nr);
  left->nr += right->nr;
  right->nr = 0;
  left->next = right->next;
  if (right->next)
    right->next->prev = left;
}

// move everything from right to left
  static void
bptree_meta_merge2(struct bpnode * const left, struct bpnode * const right)
{
  debug_assert((left->leaf == false) && (right->leaf == false));
  debug_assert((left->nr + right->nr) <= BPTREE_META_FO);
  memcpy(&(left->key[left->nr]), &(right->key[0]), sizeof(right->key[0]) * right->nr);
  memcpy(&(left->sub[left->nr]), &(right->sub[0]), sizeof(right->sub[0]) * right->nr);
  left->nr += right->nr;
  right->nr = 0;
}

// return true if a key is deleted; return false if not found
  static bool
bptree_del_rec(struct bptree * const tree, struct bpnode * const node,
    const struct kref * const key)
{
  // on leaf: the parent will do rebalance if necessary
  if (node->leaf)
    return bptree_leaf_del(tree, node, key);

  // internal
  const u32 id0 = bptree_meta_search_le(node, key);
  const bool r = bptree_del_rec(tree, node->sub[id0], key);
  struct bpnode * const sub0 = node->sub[id0];
  // if the child node is large enough, just return
  // watermark is 1/3 of node capacity
  if ((sub0->leaf && (sub0->nr > (BPTREE_LEAF_FO / 3))) ||
      ((!sub0->leaf) && (sub0->nr > (BPTREE_META_FO / 3)))) {
    return r;
  }

  // small child node: try merge or rebalance
  u32 sib = 0;
  // select a sibling node (sib); left or right
  if (id0 && ((id0 + 1) < node->nr)) // select a smaller sibling
    sib = (node->sub[id0-1]->nr < node->sub[id0+1]->nr) ? (id0 - 1) : (id0 + 1);
  else // there is only one choice
    sib = id0 ? (id0 - 1) : (id0 + 1);

  // play with idl and idr (idl + 1 == idr)
  const u32 idl = (id0 < sib) ? id0 : sib;
  const u32 idr = idl + 1;

  if (node->sub[id0]->leaf) { // children are leaf nodes
    if ((node->sub[idl]->nr + node->sub[idr]->nr) <= BPTREE_LEAF_FO) { // merge
      bptree_leaf_merge2(node->sub[idl], node->sub[idr]);
      bptree_meta_del(tree, node, idr);
    } else { // rebalance
      bptree_leaf_balance(node->sub[idl], node->sub[idr]);
      // update anchor
      free(node->key[idr]);
      node->key[idr] = kv_dup_key(node->sub[idr]->kvs[0]);
    }
  } else { // children are meta nodes
    if ((node->sub[idl]->nr + node->sub[idr]->nr) <= BPTREE_META_FO) { // merge
      bptree_meta_merge2(node->sub[idl], node->sub[idr]);
      bptree_meta_del(tree, node, idr);
    } else { // rebalance
      bptree_meta_rebalance(node->sub[idl], node->sub[idr]);
      // update anchor
      free(node->key[idr]);
      node->key[idr] = kv_dup_key(node->sub[idr]->key[0]);
    }
  }
  return r;
}

  bool
bptree_del(struct bptree * const tree, const struct kref * const key)
{
  struct bpnode * const root = tree->root;
  const bool r = bptree_del_rec(tree, root, key);
  // root may get single child after merge; depth -1
  if ((root->leaf == false) && (root->nr == 1)) {
    tree->root = root->sub[0];
    tree->depth--;
    free(root->key[0]);
    slab_free_unsafe(tree->slab, root);
  }
  return r;
}
// }}} del

// misc {{{
  static void
bptree_clean_rec(struct bptree * const tree, struct bpnode * const node)
{
  if (node->leaf) {
    if (tree->mm.free) {
      for (u32 i = 0; i < node->nr; i++) {
        struct kv * const kv = (typeof(kv))(node->kvs[i]);
        tree->mm.free(kv, tree->mm.priv);
      }
    }
  } else {
    for (u32 i = 0; i < node->nr; i++) {
      struct kv * const kv = (typeof(kv))(node->key[i]);
      free(kv);
      bptree_clean_rec(tree, node->sub[i]);
    }
  }
  slab_free_unsafe(tree->slab, node);
}

  void
bptree_clean(struct bptree * const tree)
{
  bptree_clean_rec(tree, tree->root);
  tree->root = bptree_alloc_node(tree, true);
}

  void
bptree_destroy(struct bptree * const tree)
{
  bptree_clean(tree);
  slab_free_unsafe(tree->slab, tree->root);
  slab_destroy(tree->slab);
  free(tree);
}

  static size_t
bptree_count_rec(struct bpnode * const node)
{
  if (node->leaf)
    return node->nr;

  size_t count = 0;
  for (u32 i = 0; i < node->nr; i++)
    count += bptree_count_rec(node->sub[i]);

  return count;
}

  void
bptree_fprint(struct bptree * const tree, FILE * const out)
{
  fprintf(out, "bptree: depth %lu keys %zu\n", tree->depth, bptree_count_rec(tree->root));
}
// }}} misc

// iter {{{
struct bptree_iter {
  struct bptree * tree;
  struct bpnode * curr;
  u32 i;
};

  struct bptree_iter *
bptree_iter_create(struct bptree * const tree)
{
  struct bptree_iter * const iter = malloc(sizeof(*iter));
  if (iter == NULL)
    return NULL;
  struct bpnode * node = tree->root;

  while (node->leaf == false)
    node = node->sub[0];
  while (node && (node->nr == 0))
    node = node->next;

  iter->tree = tree;
  iter->curr = node;
  iter->i = 0;
  return iter;
}

  void
bptree_iter_seek(struct bptree_iter * const iter, const struct kref * const key)
{
  struct bpnode * leaf = bptree_down_leaf(iter->tree, key);
  u32 idx = bptree_leaf_search_ge(leaf, key) & ~BPTREE_CMP_MATCH;
  while (leaf && (idx >= leaf->nr)) {
    leaf = leaf->next;
    idx = 0;
  }
  iter->curr = leaf; // could be NULL
  iter->i = idx;
}

  void
bptree_iter_seek_le(struct bptree_iter * const iter, const struct kref * const key)
{
  bptree_iter_seek(iter, key);
  if (bptree_iter_valid(iter)) { // valid: may move backward
    struct bpnode * const leaf = iter->curr;
    if (kref_kv_match(key, leaf->kvs[iter->i]))
      return;
    // move backward
    if (iter->i) {
      iter->i--;
    } else {
      iter->curr = leaf->prev;
      iter->i = iter->curr ? (iter->curr->nr - 1) : 0;
    }
  } else {
    // get the largest key
    struct bpnode * node = iter->tree->root;
    while (!node->leaf) {
      debug_assert(node->nr);
      node = node->sub[node->nr - 1];
    }
    debug_assert(node->leaf);
    if (node->nr) {
      iter->curr = node;
      iter->i = node->nr - 1;
    } else {
      iter->curr = NULL;
      iter->i = 0;
    }
  }
}

  bool
bptree_iter_valid(struct bptree_iter * const iter)
{
  return iter->curr != NULL;
}

  struct kv *
bptree_iter_peek(struct bptree_iter * const iter, struct kv * const out)
{
  if (!bptree_iter_valid(iter))
    return NULL;
  struct kv * const ret = iter->tree->mm.out(iter->curr->kvs[iter->i], out);
  return ret;
}

  bool
bptree_iter_kref(struct bptree_iter * const iter, struct kref * const kref)
{
  if (!bptree_iter_valid(iter))
    return false;
  kref_ref_kv(kref, iter->curr->kvs[iter->i]);
  return true;
}

  bool
bptree_iter_kvref(struct bptree_iter * const iter, struct kvref * const kvref)
{
  if (!bptree_iter_valid(iter))
    return false;
  kvref_ref_kv(kvref, iter->curr->kvs[iter->i]);
  return true;
}

  static void
bptree_iter_fix(struct bptree_iter * const iter)
{
  while (iter->curr && (iter->i >= iter->curr->nr)) {
    iter->curr = iter->curr->next;
    iter->i = 0;
  }
}

  void
bptree_iter_skip1(struct bptree_iter * const iter)
{
  if (bptree_iter_valid(iter)) {
    iter->i++;
    bptree_iter_fix(iter);
  }
}

  void
bptree_iter_skip(struct bptree_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (!bptree_iter_valid(iter))
      return;
    iter->i++;
    bptree_iter_fix(iter);
  }
}

  struct kv *
bptree_iter_next(struct bptree_iter * const iter, struct kv * const out)
{
  struct kv * const ret = bptree_iter_peek(iter, out);
  bptree_iter_skip1(iter);
  return ret;
}

  bool
bptree_iter_inp(struct bptree_iter * const iter, kv_inp_func uf, void * const priv)
{
  struct kv * const kv = iter->curr ? iter->curr->kvs[iter->i] : NULL;
  uf(kv, priv);
  return kv != NULL;
}

  void
bptree_iter_destroy(struct bptree_iter * const iter)
{
  free(iter);
}
// }}} iter

// api {{{
const struct kvmap_api kvmap_api_bptree = {
  .ordered = true,
  .unique = true,
  .put = (void *)bptree_put,
  .get = (void *)bptree_get,
  .probe = (void *)bptree_probe,
  .del = (void *)bptree_del,
  .inpr = (void *)bptree_inp,
  .inpw = (void *)bptree_inp,
  .merge = (void *)bptree_merge,
  .iter_create = (void *)bptree_iter_create,
  .iter_seek = (void *)bptree_iter_seek,
  .iter_valid = (void *)bptree_iter_valid,
  .iter_peek = (void *)bptree_iter_peek,
  .iter_kref = (void *)bptree_iter_kref,
  .iter_kvref = (void *)bptree_iter_kvref,
  .iter_skip1 = (void *)bptree_iter_skip1,
  .iter_skip = (void *)bptree_iter_skip,
  .iter_next = (void *)bptree_iter_next,
  .iter_inp = (void *)bptree_iter_inp,
  .iter_destroy = (void *)bptree_iter_destroy,
  .clean = (void *)bptree_clean,
  .destroy = (void *)bptree_destroy,
  .fprint = (void *)bptree_fprint,
};

  static void *
bptree_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  if (strcmp(name, "bptree"))
    return NULL;
  (void)args;
  return bptree_create(mm);
}

__attribute__((constructor))
  static void
bptree_kvmap_api_init(void)
{
  kvmap_api_register(0, "bptree", "", bptree_kvmap_api_create, &kvmap_api_bptree);
}
// }}} api

#undef BPTREE_META_FO
#undef BPTREE_LEAF_FO
// }}} bptree

// rdb {{{
#ifdef ROCKSDB
#define ROCKSDB_SYNC_SIZE ((1lu<<25))
#include "include/rocksdb/c.h"
struct rdb {
  rocksdb_t * db;
  rocksdb_filterpolicy_t * bf;
  rocksdb_options_t * dopt;
  u64 sync_size;
  rocksdb_writeoptions_t * wopt;
  rocksdb_writeoptions_t * wopt_sync;
  rocksdb_readoptions_t * ropt;
  rocksdb_cache_t * cache;
  char * path;
  char * err;
};

  struct rdb *
rdb_create(const char * const path, const u64 arg)
{
  rocksdb_options_t* const dopt = rocksdb_options_create();
  rocksdb_options_set_compression(dopt, 0);
  rocksdb_options_set_create_if_missing(dopt, 1);

  // statistics of everything; uncomment to enable
  //rocksdb_options_enable_statistics(dopt);

  // Total ordered database, flash storage
  // https://github.com/facebook/rocksdb/wiki/RocksDB-Tuning-Guide
  rocksdb_env_t * const env = rocksdb_create_default_env();
  rocksdb_env_set_background_threads(env, 4);
  rocksdb_options_set_env(dopt, env);


  // table options
  rocksdb_block_based_table_options_t* const topt = rocksdb_block_based_options_create();
  // bf
  rocksdb_filterpolicy_t * bf = rocksdb_filterpolicy_create_bloom(10);
  rocksdb_block_based_options_set_filter_policy(topt, bf);

  // rocksdb_options_set_block_based_table_factory(dopt, topt);

  struct rdb * const rdb = malloc(sizeof(*rdb));
  if (rdb == NULL)
    return NULL;

  if (arg != 0) {
    rdb->db = rocksdb_open(dopt, path, &rdb->err);
    // read-write
  } else {
    rdb->db = rocksdb_open_for_read_only(dopt, path, 1, &rdb->err);
    // read-only
  }

  if (rdb->db == NULL) {
    free(rdb);
    return NULL;
  }

  rdb->path = strdup(path);
  rdb->dopt = dopt;
  rocksdb_block_based_options_destroy(topt);

  rdb->bf = bf;
  rdb->sync_size = 0;
  rdb->wopt = rocksdb_writeoptions_create();
  rdb->wopt_sync = rocksdb_writeoptions_create();
  rocksdb_writeoptions_set_sync(rdb->wopt_sync, 1);
  rdb->ropt = rocksdb_readoptions_create();
  rdb->cache = NULL;
  rocksdb_env_destroy(env);
  rocksdb_readoptions_set_fill_cache(rdb->ropt, 1);
  rocksdb_readoptions_set_verify_checksums(rdb->ropt, 0);
  return rdb;
}

  struct kv *
rdb_get(struct rdb * const map, const struct kref * const key, struct kv * const out)
{
  size_t vlen;
  char * const ret = rocksdb_get(map->db, map->ropt, (const char *)key->ptr,
      (size_t)key->len, &vlen, &map->err);
  if (ret) {
    if (out) {
      kv_refill(out, key->ptr, key->len, ret, vlen);
      free(ret);
      return out;
    } else {
      struct kv * const new = kv_create(key->ptr, key->len, ret, vlen);
      free(ret);
      return new;
    }
  } else {
    return NULL;
  }
}

  bool
rdb_probe(struct rdb * const map, const struct kref * const key)
{
  size_t vlen;
  char * const ret = rocksdb_get(map->db, map->ropt, (const char *)key->ptr,
      (size_t)key->len, &vlen, &map->err);
  free(ret);
  return ret != NULL;
}

  bool
rdb_put(struct rdb * const map, struct kv * const kv)
{
  map->sync_size += (kv->klen + kv->vlen);
  const bool do_sync = (map->sync_size >= ROCKSDB_SYNC_SIZE);
  if (do_sync)
    map->sync_size -= ROCKSDB_SYNC_SIZE;

  rocksdb_put(map->db, (do_sync ? map->wopt_sync : map->wopt),
      (const char *)kv->kv, (size_t)kv->klen,
      (const char *)kv_vptr_c(kv), (size_t)kv->vlen, &map->err);
  return true;
}

  bool
rdb_del(struct rdb * const map, const struct kref * const key)
{
  rocksdb_delete(map->db, map->wopt, (const char *)key->ptr, (size_t)key->len, &map->err);
  return true;
}

  void
rdb_destroy(struct rdb * const map)
{
  // XXX: rocksdb/gflags has memoryleak on exit.
  //rocksdb_filterpolicy_destroy(map->bf); // destroyed by rocksdb_options_destroy()
  rocksdb_close(map->db);
  rocksdb_readoptions_destroy(map->ropt);
  rocksdb_writeoptions_destroy(map->wopt);
  rocksdb_writeoptions_destroy(map->wopt_sync);
  if (map->cache)
    rocksdb_cache_destroy(map->cache);
  // uncomment to remove db files
  //rocksdb_destroy_db(map->dopt, map->path, &map->err);
  free(map->path);
  rocksdb_options_destroy(map->dopt);
  free(map);
}

  void
rdb_fprint(struct rdb * const map, FILE * const out)
{
  char * str = rocksdb_options_statistics_get_string(map->dopt);
  if (str)
    fprintf(out, "%s", str);
}

  struct rdb_iter *
rdb_iter_create(struct rdb * const map)
{
  struct rdb_iter * const iter = (typeof(iter))rocksdb_create_iterator(map->db, map->ropt);
  return iter;
}

  void
rdb_iter_seek(struct rdb_iter * const iter, const struct kref * const key)
{
  rocksdb_iter_seek((rocksdb_iterator_t *)iter, (const char *)key->ptr, (size_t)key->len);
}

  bool
rdb_iter_valid(struct rdb_iter * const iter)
{
  struct rocksdb_iterator_t * riter = (typeof(riter))iter;
  return rocksdb_iter_valid(riter);
}

  struct kv *
rdb_iter_peek(struct rdb_iter * const iter, struct kv * const out)
{
  struct rocksdb_iterator_t * riter = (typeof(riter))iter;
  if (rocksdb_iter_valid(riter)) {
    size_t klen, vlen;
    const char * const key = rocksdb_iter_key(riter, &klen);
    const char * const value = rocksdb_iter_value(riter, &vlen);
    if (out) {
      kv_refill(out, (u8 *)key, (u32)klen, (u8 *)value, (u32)vlen);
      return out;
    } else {
      return kv_create((u8 *)key, (u32)klen, (u8 *)value, (u32)vlen);
    }
  }
  return NULL;
}

  void
rdb_iter_skip1(struct rdb_iter * const iter)
{
  struct rocksdb_iterator_t * riter = (typeof(riter))iter;
  if (rocksdb_iter_valid(riter))
    rocksdb_iter_next(riter);
}

  void
rdb_iter_skip(struct rdb_iter * const iter, const u32 nr)
{
  struct rocksdb_iterator_t * riter = (typeof(riter))iter;
  for (u32 i = 0; i < nr; i++) {
    if (!rocksdb_iter_valid(riter))
      break;
    rocksdb_iter_next(riter);
  }
}

  struct kv *
rdb_iter_next(struct rdb_iter * const iter, struct kv * const out)
{
  struct kv * const ret = rdb_iter_peek(iter, out);
  rdb_iter_skip1(iter);
  return ret;
}

  void
rdb_iter_destroy(struct rdb_iter * const iter)
{
  rocksdb_iter_destroy((rocksdb_iterator_t *)iter);
}

const struct kvmap_api kvmap_api_rdb = {
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .put = (void *)rdb_put,
  .get = (void *)rdb_get,
  .probe = (void *)rdb_probe,
  .del = (void *)rdb_del,
  .iter_create = (void *)rdb_iter_create,
  .iter_seek = (void *)rdb_iter_seek,
  .iter_valid = (void *)rdb_iter_valid,
  .iter_peek = (void *)rdb_iter_peek,
  .iter_skip1 = (void *)rdb_iter_skip1,
  .iter_skip = (void *)rdb_iter_skip,
  .iter_next = (void *)rdb_iter_next,
  .iter_destroy = (void *)rdb_iter_destroy,
  .destroy = (void *)rdb_destroy,
  .fprint = (void *)rdb_fprint,
};

  static void *
rdb_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  if (strcmp(name, "rdb") != 0)
    return NULL;
  (void)mm;
  return rdb_create(args[0], a2u64(args[1]));
}

// alternatively, call the register function from main()
__attribute__((constructor))
  static void
rdb_kvmap_api_init(void)
{
  kvmap_api_register(2, "rdb", "<path> <cache-mb>", rdb_kvmap_api_create, &kvmap_api_rdb);
}
#endif // ROCKSDB
// }}} rdb

// ldb {{{
#ifdef LEVELDB
#define LEVELDB_SYNC_SIZE ((1lu<<25))
#include <leveldb/c.h>
struct ldb {
  leveldb_t * db;
  leveldb_options_t * dopt;
  leveldb_filterpolicy_t * bf;
  u64 sync_size;
  leveldb_writeoptions_t * wopt;
  leveldb_writeoptions_t * wopt_sync;
  leveldb_readoptions_t * ropt;
  leveldb_cache_t * cache;
  char * path;
  char * err;
};

  struct ldb *
ldb_create(const char * const path, const u64 cache_size_mb)
{
  leveldb_options_t* const dopt = leveldb_options_create();
  leveldb_options_set_compression(dopt, 0);
  leveldb_options_set_create_if_missing(dopt, 1);
  leveldb_options_set_write_buffer_size(dopt, 128lu<<20); // 2x file_size
  leveldb_options_set_max_open_files(dopt, 65536);
  leveldb_options_set_max_file_size(dopt, 64lu<<20);
  leveldb_filterpolicy_t * bf = leveldb_filterpolicy_create_bloom(10);
  leveldb_options_set_filter_policy(dopt, bf);

  leveldb_cache_t* cache = NULL;
  if (cache_size_mb) {
    cache = leveldb_cache_create_lru(cache_size_mb << 20); // MB
    leveldb_options_set_cache(dopt, cache);
  }

  struct ldb * const ldb = malloc(sizeof(*ldb));
  ldb->db = leveldb_open(dopt, path, &ldb->err);
  ldb->path = strdup(path);
  ldb->dopt = dopt;
  ldb->bf = bf;
  ldb->sync_size = 0;
  ldb->wopt = leveldb_writeoptions_create();
  ldb->wopt_sync = leveldb_writeoptions_create();
  leveldb_writeoptions_set_sync(ldb->wopt_sync, 1);
  ldb->ropt = leveldb_readoptions_create();
  ldb->cache = cache;
  return ldb;
}

  struct kv *
ldb_get(struct ldb * const map, const struct kref * const key, struct kv * const out)
{
  size_t vlen;
  char * const ret = leveldb_get(map->db, map->ropt, (const char *)key->ptr,
      (size_t)key->len, &vlen, &map->err);
  if (ret) {
    if (out) {
      kv_refill(out, key->ptr, key->len, ret, vlen);
      free(ret);
      return out;
    } else {
      struct kv * const new = kv_create(key->ptr, key->len, ret, vlen);
      free(ret);
      return new;
    }
  } else {
    return NULL;
  }
}

  bool
ldb_probe(struct ldb * const map, const struct kref * const key)
{
  size_t vlen;
  char * const ret = leveldb_get(map->db, map->ropt, (const char *)key->ptr,
      (size_t)key->len, &vlen, &map->err);
  free(ret);
  return ret != NULL;
}

  bool
ldb_put(struct ldb * const map, struct kv * const kv)
{
  map->sync_size += (kv->klen + kv->vlen);
  const bool do_sync = (map->sync_size >= LEVELDB_SYNC_SIZE);
  if (do_sync)
    map->sync_size -= LEVELDB_SYNC_SIZE;

  leveldb_put(map->db, (do_sync ? map->wopt_sync : map->wopt),
      (const char *)kv->kv, (size_t)kv->klen,
      (const char *)kv_vptr_c(kv), (size_t)kv->vlen, &map->err);
  return true;
}

  bool
ldb_del(struct ldb * const map, const struct kref * const key)
{
  leveldb_delete(map->db, map->wopt, (const char *)key->ptr, (size_t)key->len, &map->err);
  return true;
}

  void
ldb_destroy(struct ldb * const map)
{
  // XXX: leveldb/gflags has memoryleak on exit.
  leveldb_close(map->db);
  leveldb_readoptions_destroy(map->ropt);
  leveldb_writeoptions_destroy(map->wopt);
  leveldb_writeoptions_destroy(map->wopt_sync);
  leveldb_options_set_filter_policy(map->dopt, NULL);
  leveldb_filterpolicy_destroy(map->bf);
  if (map->cache)
    leveldb_cache_destroy(map->cache);
  // uncomment to remove db files
  //leveldb_destroy_db(map->dopt, map->path, &map->err);
  free(map->path);
  leveldb_options_destroy(map->dopt);
  free(map);
}

  void
ldb_fprint(struct ldb * const map, FILE * const out)
{
  char * str = leveldb_property_value(map->db, "stats");
  if (str)
    fprintf(out, "%s", str);
}

  struct ldb_iter *
ldb_iter_create(struct ldb * const map)
{
  struct ldb_iter * const iter = (typeof(iter))leveldb_create_iterator(map->db, map->ropt);
  return iter;
}

  void
ldb_iter_seek(struct ldb_iter * const iter, const struct kref * const key)
{
  leveldb_iter_seek((leveldb_iterator_t *)iter, (const char *)key->ptr, (size_t)key->len);
}

  bool
ldb_iter_valid(struct ldb_iter * const iter)
{
  struct leveldb_iterator_t * riter = (typeof(riter))iter;
  return leveldb_iter_valid(riter);
}

  struct kv *
ldb_iter_peek(struct ldb_iter * const iter, struct kv * const out)
{
  struct leveldb_iterator_t * riter = (typeof(riter))iter;
  if (leveldb_iter_valid(riter)) {
    size_t klen, vlen;
    const char * const key = leveldb_iter_key(riter, &klen);
    const char * const value = leveldb_iter_value(riter, &vlen);
    if (out) {
      kv_refill(out, (u8 *)key, (u32)klen, (u8 *)value, (u32)vlen);
      return out;
    } else {
      return kv_create((u8 *)key, (u32)klen, (u8 *)value, (u32)vlen);
    }
  }
  return NULL;
}

  void
ldb_iter_skip1(struct ldb_iter * const iter)
{
  struct leveldb_iterator_t * riter = (typeof(riter))iter;
  if (leveldb_iter_valid(riter))
    leveldb_iter_next(riter);
}

  void
ldb_iter_skip(struct ldb_iter * const iter, const u32 nr)
{
  struct leveldb_iterator_t * riter = (typeof(riter))iter;
  for (u32 i = 0; i < nr; i++) {
    if (!leveldb_iter_valid(riter))
      break;
    leveldb_iter_next(riter);
  }
}

  struct kv *
ldb_iter_next(struct ldb_iter * const iter, struct kv * const out)
{
  struct kv * const ret = ldb_iter_peek(iter, out);
  ldb_iter_skip1(iter);
  return ret;
}

  void
ldb_iter_destroy(struct ldb_iter * const iter)
{
  leveldb_iter_destroy((leveldb_iterator_t *)iter);
}

const struct kvmap_api kvmap_api_ldb = {
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .put = (void *)ldb_put,
  .get = (void *)ldb_get,
  .probe = (void *)ldb_probe,
  .del = (void *)ldb_del,
  .iter_create = (void *)ldb_iter_create,
  .iter_seek = (void *)ldb_iter_seek,
  .iter_valid = (void *)ldb_iter_valid,
  .iter_peek = (void *)ldb_iter_peek,
  .iter_skip1 = (void *)ldb_iter_skip1,
  .iter_skip = (void *)ldb_iter_skip,
  .iter_next = (void *)ldb_iter_next,
  .iter_destroy = (void *)ldb_iter_destroy,
  .destroy = (void *)ldb_destroy,
  .fprint = (void *)ldb_fprint,
};

  static void *
ldb_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  if (strcmp(name, "ldb") != 0)
    return NULL;
  (void)mm;
  return ldb_create(args[0], a2u64(args[1]));
}

// alternatively, call the register function from main()
__attribute__((constructor))
  static void
ldb_kvmap_api_init(void)
{
  kvmap_api_register(2, "ldb", "<path> <cache-mb>", ldb_kvmap_api_create, &kvmap_api_ldb);
}
#endif // LEVELDB
// }}} ldb

// lmdb {{{
#ifdef LMDB
#include <lmdb.h>
#define MAIN_DBI (1)
  struct lmdb *
lmdb_open(const char * const path)
{
  MDB_env * env = NULL;
  mdb_env_create(&env);
  mdb_env_set_mapsize(env, 1lu << 39);
  mkdir(path, 0755);
  mdb_env_open(env, path, 0, 0664);
  // create an empty db
  MDB_txn * txn = NULL;
  mdb_txn_begin(env, NULL, 0, &txn);
  MDB_dbi dbi;
  mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);
  mdb_txn_commit(txn);

  // dbi == MAIN_DBI
  debug_assert(dbi == MAIN_DBI);
  return (struct lmdb *)env;
}

  struct lmdb_ref *
lmdb_ref(struct lmdb * const db)
{
  MDB_txn * txn = NULL;
  // MDB_RDONLY allows concurrent reads
  // set/del will need to create a temp txn
  mdb_txn_begin((MDB_env *)db, NULL, MDB_RDONLY, &txn);
  return (struct lmdb_ref *)txn;
}

  struct lmdb *
lmdb_unref(struct lmdb_ref * const ref)
{
  MDB_env * const env = mdb_txn_env((MDB_txn *)ref);
  mdb_txn_abort((MDB_txn *)ref); // abort a read txn
  return (struct lmdb *)env;
}

  struct lmdb_ref *
lmdbw_ref(struct lmdb * const db)
{
  MDB_txn * txn = NULL;
  // start a write txn by default; no concurrency
  mdb_txn_begin((MDB_env *)db, NULL, 0, &txn);
  return (struct lmdb_ref *)txn;
}

  struct lmdb *
lmdbw_unref(struct lmdb_ref * const ref)
{
  MDB_env * const env = mdb_txn_env((MDB_txn *)ref);
  mdb_txn_commit((MDB_txn *)ref); // commit a write txn
  return (struct lmdb *)env;
}

  struct kv *
lmdb_get(struct lmdb_ref * const ref, const struct kref * const key, struct kv * const out)
{
  MDB_val mkey = {.mv_size = key->len, .mv_data = (void *)key->ptr};
  MDB_val mv;
  const int r = mdb_get((MDB_txn *)ref, MAIN_DBI, &mkey, &mv);
  if (r == MDB_SUCCESS) {
    if (out) {
      kv_refill_kref_v(out, key, mv.mv_data, (u32)mv.mv_size);
      return out;
    } else {
      return kv_create_kref(key, mv.mv_data, (u32)mv.mv_size);
    }
  } else { // not found
    return NULL;
  }
}

  struct kv *
lmdb1_get(struct lmdb * const db, const struct kref * const key, struct kv * const out)
{
  struct lmdb_ref * const ref = lmdb_ref(db);
  struct kv * const ret = lmdb_get(ref, key, out);
  lmdb_unref(ref);
  return ret;
}

  bool
lmdb_probe(struct lmdb_ref * const ref, const struct kref * const key)
{
  MDB_val mkey = {.mv_size = key->len, .mv_data = (void *)key->ptr};
  MDB_val mv;
  const int r = mdb_get((MDB_txn *)ref, MAIN_DBI, &mkey, &mv);
  return r == MDB_SUCCESS;
}

  bool
lmdb1_probe(struct lmdb * const db, const struct kref * const key)
{
  struct lmdb_ref * const ref = lmdb_ref(db);
  const bool ret = lmdb_probe(ref, key);
  lmdb_unref(ref);
  return ret;
}

  bool
lmdb_put(struct lmdb_ref * const ref, struct kv * const kv)
{
  MDB_env * const env = mdb_txn_env((MDB_txn *)ref);
  return lmdb1_put((struct lmdb *)env, kv);
}

  bool
lmdb1_put(struct lmdb * const db, struct kv * const kv)
{
  MDB_env * const env = (typeof(env))db;
  MDB_txn * wtxn = NULL;
  if (mdb_txn_begin(env, NULL, 0, &wtxn) != MDB_SUCCESS)
    return false;

  MDB_val mkey = {.mv_size = kv->klen, .mv_data = kv_kptr(kv)};
  MDB_val mv = {.mv_size = kv->vlen, .mv_data = kv_vptr(kv)};
  if (mdb_put(wtxn, MAIN_DBI, &mkey, &mv, 0) == MDB_SUCCESS) {
    return mdb_txn_commit(wtxn) == MDB_SUCCESS;
  } else {
    mdb_txn_abort(wtxn);
    return false;
  }
}

  bool
lmdbw_put(struct lmdb_ref * const ref, struct kv * const kv)
{
  MDB_val mkey = {.mv_size = kv->klen, .mv_data = kv_kptr(kv)};
  MDB_val mv = {.mv_size = kv->vlen, .mv_data = kv_vptr(kv)};
  return mdb_put((MDB_txn *)ref, MAIN_DBI, &mkey, &mv, 0) == MDB_SUCCESS;
}

  bool
lmdb_del(struct lmdb_ref * const ref, const struct kref * const key)
{
  MDB_env * const env = mdb_txn_env((MDB_txn *)ref);
  return lmdb1_del((struct lmdb *)env, key);
}

  bool
lmdb1_del(struct lmdb * const db, const struct kref * const key)
{
  MDB_env * const env = (typeof(env))db;
  MDB_txn * wtxn = NULL;
  if (mdb_txn_begin(env, NULL, 0, &wtxn) != MDB_SUCCESS)
    return false;

  MDB_val mkey = {.mv_size = key->len, .mv_data = (void *)key->ptr};
  if (mdb_del(wtxn, MAIN_DBI, &mkey, NULL) == MDB_SUCCESS) {
    return mdb_txn_commit(wtxn) == MDB_SUCCESS;
  } else {
    mdb_txn_abort(wtxn);
    return false;
  }
}

  bool
lmdbw_del(struct lmdb_ref * const ref, const struct kref * const key)
{
  MDB_val mkey = {.mv_size = key->len, .mv_data = (void *)key->ptr};
  return mdb_del((MDB_txn *)ref, MAIN_DBI, &mkey, NULL) == MDB_SUCCESS;
}

  void
lmdb_clean(struct lmdb * const map)
{
  MDB_env * const env = (typeof(env))map;
  MDB_txn * txn = NULL;
  mdb_txn_begin(env, NULL, 0, &txn);
  mdb_drop(txn, MAIN_DBI, 0); // 0 to empty the DB
  mdb_txn_commit(txn);
}

  void
lmdb_destroy(struct lmdb * const map)
{
  MDB_env * const env = (typeof(env))map;
  //lmdb_clean(map);
  mdb_dbi_close(env, MAIN_DBI);
  mdb_env_close(env);
}

  void
lmdb_fprint(struct lmdb * const map, FILE * const out)
{
  MDB_env * const env = (typeof(env))map;
  MDB_txn * txn = NULL;
  mdb_txn_begin(env, NULL, 0, &txn);
  MDB_stat st;
  mdb_stat(txn, MAIN_DBI, &st);
  fprintf(out, "psize %u depth %u bp %lu lp %lu op %lu entries %lu\n", st.ms_psize, st.ms_depth,
      st.ms_branch_pages, st.ms_leaf_pages, st.ms_overflow_pages, st.ms_entries);
  mdb_txn_abort(txn);
}

  struct lmdb_iter *
lmdb_iter_create(struct lmdb_ref * const ref)
{
  MDB_cursor * cursor;
  if (mdb_cursor_open((MDB_txn *)ref, MAIN_DBI, &cursor) == MDB_SUCCESS)
    return (struct lmdb_iter *)cursor;
  else
    return NULL;
}

  struct lmdb_iter *
lmdb1_iter_create(struct lmdb * const db)
{
  struct lmdb_ref * const ref = lmdb_ref(db);
  struct lmdb_iter * const iter = lmdb_iter_create(ref);
  if (iter) {
    return iter;
  } else {
    lmdb_unref(ref);
    return NULL;
  }
}

  void
lmdb_iter_seek(struct lmdb_iter * const iter, const struct kref * const key)
{
  MDB_val mkey = {.mv_size = key->len, .mv_data = (void *)key->ptr};
  mdb_cursor_get((MDB_cursor *)iter, &mkey, NULL, MDB_SET_RANGE);
}

  bool
lmdb_iter_valid(struct lmdb_iter * const iter)
{
  MDB_val mkey, mv;
  return mdb_cursor_get((MDB_cursor *)iter, &mkey, &mv, MDB_GET_CURRENT) == MDB_SUCCESS;
}

  struct kv *
lmdb_iter_peek(struct lmdb_iter * const iter, struct kv * const out)
{
  MDB_val mkey, mv;
  if (mdb_cursor_get((MDB_cursor *)iter, &mkey, &mv, MDB_GET_CURRENT) == MDB_SUCCESS) {
    if (out) {
      kv_refill(out, mkey.mv_data, (u32)mkey.mv_size, mv.mv_data, (u32)mv.mv_size);
      return out;
    } else {
      return kv_create(mkey.mv_data, (u32)mkey.mv_size, mv.mv_data, (u32)mv.mv_size);
    }
  } else {
    return NULL;
  }
}

  void
lmdb_iter_skip1(struct lmdb_iter * const iter)
{
  mdb_cursor_get((MDB_cursor *)iter, NULL, NULL, MDB_NEXT);
}


  void
lmdb_iter_skip(struct lmdb_iter * const iter, const u32 nr)
{
  for (u32 i = 0; i < nr; i++) {
    if (mdb_cursor_get((MDB_cursor *)iter, NULL, NULL, MDB_NEXT) != MDB_SUCCESS)
      return;
  }
}

  struct kv *
lmdb_iter_next(struct lmdb_iter * const iter, struct kv * const out)
{
  struct kv * const ret = lmdb_iter_peek(iter, out);
  lmdb_iter_skip1(iter);
  return ret;
}

  void
lmdb_iter_destroy(struct lmdb_iter * const iter)
{
  mdb_cursor_close((MDB_cursor *)iter);
}

  void
lmdb1_iter_destroy(struct lmdb_iter * const iter)
{
  MDB_txn * const txn = mdb_cursor_txn((MDB_cursor *)iter);
  lmdb_iter_destroy(iter);
  mdb_txn_abort(txn);
}

// use read-only ref for fastest read; slow write
const struct kvmap_api kvmap_api_lmdb = {
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .put = (void *)lmdb_put,
  .get = (void *)lmdb_get,
  .probe = (void *)lmdb_probe,
  .del = (void *)lmdb_del,
  .iter_create = (void *)lmdb_iter_create,
  .iter_seek = (void *)lmdb_iter_seek,
  .iter_valid = (void *)lmdb_iter_valid,
  .iter_peek = (void *)lmdb_iter_peek,
  .iter_skip1 = (void *)lmdb_iter_skip1,
  .iter_skip = (void *)lmdb_iter_skip,
  .iter_next = (void *)lmdb_iter_next,
  .iter_destroy = (void *)lmdb_iter_destroy,
  .ref = (void *)lmdb_ref,
  .unref = (void *)lmdb_unref,
  .destroy = (void *)lmdb_destroy,
  .fprint = (void *)lmdb_fprint,
};

// use read-write ref for fastest exclusive write; always mutual exclusive
const struct kvmap_api kvmap_api_lmdbw = {
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .put = (void *)lmdbw_put,
  .get = (void *)lmdb_get,
  .probe = (void *)lmdb_probe,
  .del = (void *)lmdbw_del,
  .iter_create = (void *)lmdb_iter_create,
  .iter_seek = (void *)lmdb_iter_seek,
  .iter_valid = (void *)lmdb_iter_valid,
  .iter_peek = (void *)lmdb_iter_peek,
  .iter_skip1 = (void *)lmdb_iter_skip1,
  .iter_skip = (void *)lmdb_iter_skip,
  .iter_next = (void *)lmdb_iter_next,
  .iter_destroy = (void *)lmdb_iter_destroy,
  .ref = (void *)lmdbw_ref,
  .unref = (void *)lmdbw_unref,
  .destroy = (void *)lmdb_destroy,
  .fprint = (void *)lmdb_fprint,
};

// no ref/unref, balanced read/write
const struct kvmap_api kvmap_api_lmdb1 = {
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .put = (void *)lmdb1_put,
  .get = (void *)lmdb1_get,
  .probe = (void *)lmdb1_probe,
  .del = (void *)lmdb1_del,
  .iter_create = (void *)lmdb1_iter_create,
  .iter_seek = (void *)lmdb_iter_seek,
  .iter_valid = (void *)lmdb_iter_valid,
  .iter_peek = (void *)lmdb_iter_peek,
  .iter_skip1 = (void *)lmdb_iter_skip1,
  .iter_skip = (void *)lmdb_iter_skip,
  .iter_next = (void *)lmdb_iter_next,
  .iter_destroy = (void *)lmdb1_iter_destroy,
  .destroy = (void *)lmdb_destroy,
  .fprint = (void *)lmdb_fprint,
};

  static void *
lmdb_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  if (strcmp(name, "lmdb") && strcmp(name, "lmdbw") && strcmp(name, "lmdb1"))
    return NULL;
  (void)mm;
  return lmdb_open(args[0]);
}

// alternatively, call the register function from main()
__attribute__((constructor))
  static void
lmdb_kvmap_api_init(void)
{
  kvmap_api_register(1, "lmdb", "<path>", lmdb_kvmap_api_create, &kvmap_api_lmdb);
  kvmap_api_register(1, "lmdbw", "<path>", lmdb_kvmap_api_create, &kvmap_api_lmdbw);
  kvmap_api_register(1, "lmdb1", "<path>", lmdb_kvmap_api_create, &kvmap_api_lmdb1);
}
#endif // LMDB
// }}} lmdb

// kvell {{{
#ifdef KVELL
// https://github.com/wuxb45/KVell
// make libkvell.so and install to /usr/local/lib
// https://github.com/wuxb45/KVell/blob/master/kvell.h
  extern void
kvell_init(const char * prefix, const char * nd, const char * wpd, const char * cgb, const char * qd);

  extern void
kvell_get_submit(const void * key, size_t klen, const uint64_t hash, void (*func)(void * item, uint64_t arg1, uint64_t arg2), uint64_t arg1, uint64_t arg2);

  extern void
kvell_put_submit(const void * key, size_t klen, const uint64_t hash, const void * value, size_t vlen, void (*func)(void * item, uint64_t arg1, uint64_t arg2), uint64_t arg1, uint64_t arg2);

  extern void
kvell_del_submit(const void * key, size_t klen, const uint64_t hash, void (*func)(void * item, uint64_t arg1, uint64_t arg2), uint64_t arg1, uint64_t arg2);

// XXX does 50 scans
  extern void
kvell_scan50(const void * key, size_t klen, const uint64_t hash, void (*func)(void * item, uint64_t arg1, uint64_t arg2), uint64_t arg1, uint64_t arg2);

  void *
kvell_create(char ** args)
{
  kvell_init(args[0], args[1], args[2], args[3], args[4]);

  struct vctr ** const vctrs = malloc(sizeof(vctrs[0]) * 4); // SET/DEL/GET/SCAN
  for (u32 i = 0; i < 4; i++) {
    vctrs[i] = vctr_create(1lu << 16);
  }
  return vctrs;
}

  static void
kvell_cb(void * item, u64 x, u64 y)
{
  (void)item;
  (void)x;
  (void)y;
}

  static void
kvelll_cb(void * item, u64 vctr_ptr, u64 t0)
{
  (void)item;
  struct vctr * const vctr = (typeof(vctr))vctr_ptr;
  const u64 dt_us = (time_diff_nsec(t0) + 999) / 1000;
  vctr_add1_atomic(vctr, dt_us < (1lu << 16) ? dt_us : (1lu << 16)-1);
}

// GET
  struct kv *
kvell_get(void * const map, const struct kref * const key, struct kv * const out)
{
  (void)map;
  kvell_get_submit(key->ptr, key->len, kv_crc32c_extend(key->hash32), kvell_cb, 0, 0);
  return out;
}

  struct kv *
kvelll_get(void * const map, const struct kref * const key, struct kv * const out)
{
  struct vctr ** const vctrs = map;
  kvell_get_submit(key->ptr, key->len, kv_crc32c_extend(key->hash32), kvelll_cb, (u64)vctrs[2], time_nsec());
  return out;
}

// PROBE
  bool
kvell_probe(void * const map, const struct kref * const key)
{
  (void)map;
  kvell_get_submit(key->ptr, key->len, kv_crc32c_extend(key->hash32), kvell_cb, 0, 0);
  return true;
}

  bool
kvelll_probe(void * const map, const struct kref * const key)
{
  struct vctr ** const vctrs = map;
  kvell_get_submit(key->ptr, key->len, kv_crc32c_extend(key->hash32), kvelll_cb, (u64)vctrs[2], time_nsec());
  return true;
}

// SET
  bool
kvell_put(void * const map, struct kv * const kv)
{
  (void)map;
  kvell_put_submit(kv_kptr(kv), kv->klen, kv->hash, kv_vptr(kv), kv->vlen, kvell_cb, 0, 0);
  return true;
}

  bool
kvelll_put(void * const map, struct kv * const kv)
{
  struct vctr ** const vctrs = map;
  kvell_put_submit(kv_kptr(kv), kv->klen, kv->hash, kv_vptr(kv), kv->vlen, kvelll_cb, (u64)vctrs[0], time_nsec());
  return true;
}

// DEL
  bool
kvell_del(void * const map, const struct kref * const key)
{
  (void)map;
  kvell_del_submit(key->ptr, key->len, kv_crc32c_extend(key->hash32), kvell_cb, 0, 0);
  return true;
}

  bool
kvelll_del(void * const map, const struct kref * const key)
{
  struct vctr ** const vctrs = map;
  kvell_del_submit(key->ptr, key->len, kv_crc32c_extend(key->hash32), kvelll_cb, (u64)vctrs[1], time_nsec());
  return true;
}

  void
kvell_clean(void * const map)
{
  (void)map;
}

  void
kvell_destroy(void * const map)
{
  sleep(2); // wait for async completion
  struct vctr ** const vctrs = map;
  for (u32 i = 0; i < 4; i++)
    vctr_destroy(vctrs[i]);
  free(map);
}

  void
kvell_latency_fprint(void * const map, FILE * const out)
{
  sleep(1); // wait for all async completion
  struct vctr ** const vctrs = map;
  for (u32 vi = 0; vi < 4; vi++) {
    struct vctr * const v = vctrs[vi];
    u64 sum = 0;
    for (u64 i = 0; i < (1lu << 16); i++)
      sum += vctr_get(v, i);
    if (sum == 0)
      continue;

    const u64 tot = sum;
    const double totd = (double)tot;
    sum = 0;
    u64 last = 0;
    fprintf(out, "[%u] (SET/DEL/GET/SCAN50)\ntime_us  count  delta  cdf\n0 0 0 0.000\n", vi);
    for (u64 i = 1; i < (1lu << 16); i++) {
      const u64 tmp = vctr_get(v, i);
      if (tmp) {
        if ((i-1) != last)
          fprintf(out, "%lu %lu %lu %.3lf\n", i-1, sum, 0lu, (double)sum * 100.0 / totd);
        sum += tmp;
        fprintf(out, "%lu %lu %lu %.3lf\n", i, sum, tmp, (double)sum * 100.0 / totd);
        last = i;
      }
    }
    fprintf(out, "total %lu\n", tot);
    vctr_reset(v);
  }
}

  void
kvell_fprint(void * const map, FILE * const out)
{
  (void)map;
  (void)out;
}

  void *
kvell_iter_create(void * const map)
{
  return map;
}

// SCAN50
  void
kvell_iter_seek(void * const iter, const struct kref * const key)
{
  (void)iter;
  // XXX: YCSB: do everything in seek
  kvell_scan50(key->ptr, key->len, kv_crc32c_extend(key->hash32), kvell_cb, 0, 0);
}

  void
kvelll_iter_seek(void * const iter, const struct kref * const key)
{
  struct vctr ** const vctrs = iter;
  // XXX: YCSB: do everything in seek
  kvell_scan50(key->ptr, key->len, kv_crc32c_extend(key->hash32), kvelll_cb, (u64)vctrs[3], time_nsec());
}

  bool
kvell_iter_valid(void * const iter)
{
  (void)iter;
  return true;
}

  struct kv *
kvell_iter_peek(void * const iter, struct kv * const out)
{
  (void)iter;
  (void)out;
  return out;
}

  void
kvell_iter_skip1(void * const iter)
{
  (void)iter;
}

  void
kvell_iter_skip(void * const iter, const u32 nr)
{
  (void)iter;
  (void)nr;
}

  struct kv *
kvell_iter_next(void * const iter, struct kv * const out)
{
  (void)iter;
  (void)out;
  return NULL;
}

  void
kvell_iter_destroy(void * const iter)
{
  (void)iter; // is map
}

const struct kvmap_api kvmap_api_kvell = {
  .hashkey = true,
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .put = kvell_put,
  .get = kvell_get,
  .probe = kvell_probe,
  .del = kvell_del,
  .iter_create = kvell_iter_create,
  .iter_seek = kvell_iter_seek,
  .iter_valid = kvell_iter_valid,
  .iter_peek = kvell_iter_peek,
  .iter_skip1 = kvell_iter_skip1,
  .iter_skip = kvell_iter_skip,
  .iter_next = kvell_iter_next,
  .iter_destroy = kvell_iter_destroy,
  .clean = kvell_clean,
  .destroy = kvell_destroy,
  .fprint = kvell_fprint,
};

const struct kvmap_api kvmap_api_kvelll = {
  .hashkey = true,
  .ordered = true,
  .threadsafe = true,
  .unique = true,
  .async = true,
  .put = kvelll_put,
  .get = kvelll_get,
  .probe = kvelll_probe,
  .del = kvelll_del,
  .iter_create = kvell_iter_create,
  .iter_seek = kvelll_iter_seek,
  .iter_valid = kvell_iter_valid,
  .iter_peek = kvell_iter_peek,
  .iter_skip1 = kvell_iter_skip1,
  .iter_skip = kvell_iter_skip,
  .iter_next = kvell_iter_next,
  .iter_destroy = kvell_iter_destroy,
  .clean = kvell_clean,
  .destroy = kvell_destroy,
  .fprint = kvell_latency_fprint,
};

  static void *
kvell_kvmap_api_create(const char * const name, const struct kvmap_mm * const mm, char ** args)
{
  (void)mm;
  if (0 == strcmp(name, "kvell") || 0 == strcmp(name, "kvelll"))
    return kvell_create(args);
  else
    return NULL;
}

__attribute__((constructor))
  static void
kvell_kvmap_api_init(void)
{
  kvmap_api_register(5, "kvell", "<prefix> <ndisk> <wpd> <cache-GB> <queue-depth>", kvell_kvmap_api_create, &kvmap_api_kvell);
  kvmap_api_register(5, "kvelll", "<prefix> <ndisk> <wpd> <cache-GB> <queue-depth>", kvell_kvmap_api_create, &kvmap_api_kvelll);
}
#endif // KVELL
// }}} kvell

// vim:fdm=marker
