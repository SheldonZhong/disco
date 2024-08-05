#include "fs.h"
#include "sst.h"
#include "bt.h"

const struct fs_api sst_fs = {
  .mt_rcache = (void *)msst_rcache,
  .y_open_at = (void *)mssty_open_at,
  .y_open_y_at = (void *)mssty_open_y_at,
  .y_destroy = (void *)mssty_destroy,
  .y_first_key = (void *)mssty_first_key,
  .y_last_key = (void *)mssty_last_key,
  .mt_add_refcnt = (void *)msst_add_refcnt,
  .y_drop_lazy = (void *)mssty_drop_lazy,
  .y_drop = (void *)mssty_drop,
  .y_get_magic = (void *)mssty_get_magic,
  .y_iter_new = (void *)mssty_iter_new,
  .y_iter_valid = (void *)mssty_iter_valid,
  .y_get = (void *)mssty_get,
  .y_get_ts = (void *)mssty_get_ts,
  .y_get_value_ts = (void *)mssty_get_value_ts,
  .y_probe = (void *)mssty_probe,
  .y_probe_ts = (void *)mssty_probe_ts,
  .y_iter_init = (void *)mssty_iter_init,
  .y_iter_park = (void *)mssty_iter_park,
  .y_iter_seek = (void *)mssty_iter_seek,
  .y_iter_peek = (void *)mssty_iter_peek,
  .y_iter_kref = (void *)mssty_iter_kref,
  .y_iter_kvref = (void *)mssty_iter_kvref,
  .y_iter_retain = (void *)mssty_iter_retain,
  .y_iter_skip1 = (void *)mssty_iter_skip1,
  .y_fprint = (void *)mssty_fprint,
  .y_iter_ts = (void *)mssty_iter_ts,
  .y_iter_seek_null = (void *)mssty_iter_seek_null,
  .y_create_at = (void *)mssty_create_at,
  .y_build_at = (void *)ssty_build_at,
  .mt_stats = (void *)msst_stats,
  .x_open_at_reuse = (void *)msstx_open_at_reuse,
  .t_build_at = (void *)sst_build_at,
  .mt_accu_nkv_at = (void *)msst_accu_nkv_at,
  .y_comp_est_y = mssty_comp_est_ssty,
  .mt_nkv_at = (void *)msst_nkv_at,
  .mt_nr_pages_at = (void *)msst_nr_pages_at,
  .y_miter_major = (void *)mssty_miter_major,
  .y_miter_partial = (void *)mssty_miter_partial,
  .x_suffix = ".sstx",
  .y_suffix = ".ssty",
};

const struct fs_api bt_fs = {
  .mt_rcache = (void *)mbty_rcache,
  .y_open_at = (void *)mbty_open_at,
  .y_open_y_at = (void *)mbty_open_y_at,
  .y_destroy = (void *)mbty_destroy,
  .y_first_key = (void *)mbty_first_key,
  .y_last_key = (void *)mbty_last_key,
  .mt_add_refcnt = (void *)mbt_add_refcnt,
  .y_drop_lazy = (void *)mbty_drop_lazy,
  .y_drop = (void *)mbty_drop,
  .y_get_magic = (void *)mbty_get_magic,
  .y_iter_new = (void *)mbty_iter_new,
  .y_iter_valid = (void *)mbty_iter_valid,
  .y_get = (void *)mbty_get,
  .y_get_ts = (void *)mbty_get_ts,
  .y_get_value_ts = (void *)mbty_get_value_ts,
  .y_probe = (void *)mbty_probe,
  .y_probe_ts = (void *)mbty_probe_ts,
  .y_iter_init = (void *)mbty_iter_init,
  .y_iter_park = (void *)mbty_iter_park,
  .y_iter_seek = (void *)mbty_iter_seek,
  .y_iter_peek = (void *)mbty_iter_peek,
  .y_iter_kref = (void *)mbty_iter_kref,
  .y_iter_kvref = (void *)mbty_iter_kvref,
  .y_iter_retain = (void *)mbty_iter_retain,
  .y_iter_skip1 = (void *)mbty_iter_skip1,
  .y_fprint = (void *)mbty_fprint,
  .y_iter_ts = (void *)mbty_iter_ts,
  .y_iter_seek_null = (void *)mbty_iter_seek_null,
  .y_create_at = (void *)mbty_create_at,
  .y_build_at = (void *)remix_build_at,
  .mt_stats = (void *)mbt_stats,
  .x_open_at_reuse = (void *)mbtx_open_at_reuse,
  .t_build_at = (void *)bt_build_at,
  .mt_accu_nkv_at = (void *)mbt_accu_nkv_at,
  .y_comp_est_y = mbty_comp_est_remix,
  .mt_nkv_at = (void *)mbt_nkv_at,
  .mt_nr_pages_at = (void *)mbt_nr_pages_at,
  .y_miter_major = (void *)mbty_miter_major,
  .y_miter_partial = (void *)mbty_miter_partial,
  .x_suffix = ".btx",
  .y_suffix = ".remix",
};

  const struct fs_api *
get_fs(const char * name)
{
  if (strcmp(name, "sst") == 0) {
    return &sst_fs;
  }
  if (strcmp(name, "bt") == 0) {
    return &bt_fs;
  }
  return NULL;
}

