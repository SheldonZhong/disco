#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# biosnoop  Trace block device I/O and print details including issuing PID.
#           For Linux, uses BCC, eBPF.
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by I/O
# request, as well as a starting timestamp for calculating I/O latency.
#
# Adapted from bcc/biosnoop.py

from __future__ import print_function
from bcc import BPF
import argparse
import os

# arguments
examples = """examples:
    ./biosnoop           # trace all block I/O
    ./biosnoop -d /dev/sdc    # trace sdc only
"""
parser = argparse.ArgumentParser(
    description="Trace block I/O",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-d", "--disk", type=str,
    help="trace this disk only")
parser.add_argument("-t", "--trace", action="store_true",
    help="enable trace and disable aggregate report")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
"""

bpf_text += """
struct start_req_t {
    u64 ts;
    u64 data_len;
};

struct val_t {
    u64 ts;
    u64 data_len;
    u32 pid;
    char name[TASK_COMM_LEN];
};

struct tp_args {
    u64 __unused__;
    dev_t dev;
    sector_t sector;
    unsigned int nr_sector;
    unsigned int bytes;
    char rwbs[8];
    char comm[16];
    char cmd[];
};

struct hash_key {
    dev_t dev;
    u32 rwflag;
    sector_t sector;
};

struct data_t {
    u32 pid;
    u32 dev;
    u64 rwflag;
    u64 delta;
    u64 sector;
    u64 len;
    u64 ts;
    char name[TASK_COMM_LEN];
};

BPF_HASH(start, struct hash_key, struct start_req_t);
BPF_HASH(infobyreq, struct hash_key, struct val_t);

BPF_HASH(counts);

#define WRITE_COUNT 0
#define READ_COUNT  1
#define WRITE_IO    2
#define READ_IO     3

BPF_PERF_OUTPUT(events);

static dev_t ddevt(struct gendisk *disk) {
    return (disk->major  << 20) | disk->first_minor;
}

static void mark_req(struct hash_key * pkey, u64 bytes) {
    if (pkey->rwflag == 1) {
        counts.increment(WRITE_COUNT);
        counts.increment(WRITE_IO, bytes);
    } else {
        counts.increment(READ_COUNT);
        counts.increment(READ_IO, bytes);
    }
}

/*
 * The following deals with a kernel version change (in mainline 4.7, although
 * it may be backported to earlier kernels) with how block request write flags
 * are tested. We handle both pre- and post-change versions here. Please avoid
 * kernel version tests like this as much as possible: they inflate the code,
 * test, and maintenance burden.
 */
static int get_rwflag(u32 cmd_flags) {
#ifdef REQ_WRITE
    return !!(cmd_flags & REQ_WRITE);
#elif defined(REQ_OP_SHIFT)
    return !!((cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);
#else
    return !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
#endif
}

#define RWBS_LEN	8

static int get_rwflag_tp(char *rwbs) {
    for (int i = 0; i < RWBS_LEN; i++) {
        if (rwbs[i] == 'W')
            return 1;
        if (rwbs[i] == '\\0')
            return 0;
    }
    return 0;
}

// cache PID and comm by-req
static int __trace_pid_start(struct hash_key key, u64 bytes)
{
    DISK_FILTER

    struct val_t val = {
        .data_len = bytes,
        .ts = bpf_ktime_get_ns(),
    };

    mark_req(&key, bytes);
    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = bpf_get_current_pid_tgid() >> 32;
        infobyreq.update(&key, &val);
    }
    return 0;
}


int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector
    };

    return __trace_pid_start(key, req->__data_len);
}

int trace_pid_start_tp(struct tp_args *args)
{
    struct hash_key key = {
        .dev = args->dev,
        .rwflag = get_rwflag_tp(args->rwbs),
        .sector = args->sector
    };

    return __trace_pid_start(key, args->bytes);
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector
    };

    DISK_FILTER

    struct start_req_t start_req = {
        .ts = bpf_ktime_get_ns(),
        .data_len = req->__data_len
    };
    start.update(&key, &start_req);
    return 0;
}

// output
static int __trace_req_completion(void *ctx, struct hash_key key)
{
    struct val_t *valp;
    struct data_t data = {};
    u64 ts;

    ts = bpf_ktime_get_ns();
    data.ts = ts / 1000;

    valp = infobyreq.lookup(&key);
    if (valp == 0) {
        return 0;
        // data.name[0] = '?';
        // data.name[1] = 0;
    } else {
        data.pid = valp->pid;
        bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
        data.len = valp->data_len;
        data.delta = ts - valp->ts;
    }

    data.sector = key.sector;
    data.dev = key.dev;
    data.rwflag = key.rwflag;

    events.perf_submit(ctx, &data, sizeof(data));
    start.delete(&key);
    infobyreq.delete(&key);

    return 0;
}

int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    struct hash_key key = {
        .dev = ddevt(req->__RQ_DISK__),
        .rwflag = get_rwflag(req->cmd_flags),
        .sector = req->__sector
    };

    return __trace_req_completion(ctx, key);
}

int trace_req_completion_tp(struct tp_args *args)
{
    struct hash_key key = {
        .dev = args->dev,
        .rwflag = get_rwflag_tp(args->rwbs),
        .sector = args->sector
    };

    return __trace_req_completion(args, key);
}
"""
if BPF.kernel_struct_has_field(b'request', b'rq_disk') == 1:
    bpf_text = bpf_text.replace('__RQ_DISK__', 'rq_disk')
else:
    bpf_text = bpf_text.replace('__RQ_DISK__', 'q->disk')

if args.disk is not None:
    disk_path = args.disk
    if not os.path.exists(disk_path):
        print("no such disk '%s'" % args.disk)
        exit(1)

    stat_info = os.stat(disk_path)
    dev = os.major(stat_info.st_rdev) << 20 | os.minor(stat_info.st_rdev)

    disk_filter_str = """
    if(key.dev != %s) {
        return 0;
    }
    """ % (dev)

    bpf_text = bpf_text.replace('DISK_FILTER', disk_filter_str)
else:
    bpf_text = bpf_text.replace('DISK_FILTER', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# initialize BPF
b = BPF(text=bpf_text)
if BPF.tracepoint_exists("block", "block_io_start"):
    b.attach_tracepoint(tp="block:block_io_start", fn_name="trace_pid_start_tp")
elif BPF.get_kprobe_functions(b'__blk_account_io_start'):
    b.attach_kprobe(event="__blk_account_io_start", fn_name="trace_pid_start")
elif BPF.get_kprobe_functions(b'blk_account_io_start'):
    b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
else:
    print("ERROR: No found any block io start probe/tp.")
    exit()

if BPF.tracepoint_exists("block", "block_io_done"):
    b.attach_tracepoint(tp="block:block_io_done", fn_name="trace_req_completion_tp")
elif BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_req_completion")
elif BPF.get_kprobe_functions(b'blk_account_io_done'):
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_req_completion")
else:
    print("ERROR: No found any block io done probe/tp.")
    exit()


# cache disk major,minor -> diskname
diskstats = "/proc/diskstats"
disklookup = {}
with open(diskstats) as stats:
    for line in stats:
        a = line.split()
        disklookup[a[0] + "," + a[1]] = a[2]

def disk_print(d):
    major = d >> 20
    minor = d & ((1 << 20) - 1)

    disk = str(major) + "," + str(minor)
    if disk in disklookup:
        diskname = disklookup[disk]
    else:
        diskname = "<unknown>:" + disk

    return diskname

rwflg = ""
start_ts = 0
prev_ts = 0
delta = 0

P_SEQUENTIAL = 1
P_RANDOM = 2

# process event
def print_event(cpu, data, size):
    if not args.trace:
        return

    event = b["events"].event(data)

    global start_ts
    if start_ts == 0:
        start_ts = event.ts

    if event.rwflag == 1:
        rwflg = "W"
    else:
        rwflg = "R"

    delta = float(event.ts) - start_ts

    disk_name = disk_print(event.dev)

    print("%-11.6f %-14.14s %-7s %-9s %-1s %-10s %-7s" % (
        delta / 1000000, event.name.decode('utf-8', 'replace'), event.pid,
        disk_name, rwflg, event.sector, event.len), end="")
    print("%7.2f" % (float(event.delta) / 1000000))

def report_agg():
    if args.trace:
        return

    print("Report")
    counts = b['counts'].items()
    for k, v in sorted(counts, key = lambda counts: counts[0].value):
        if k.value == 0:
            print("Write I/O", v.value)
        elif k.value == 1:
            print("Read I/O", v.value)
        elif k.value == 2:
            print("Write bytes", v.value)
        elif k.value == 3:
            print("Read bytes", v.value)

# loop with callback to print_event
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        report_agg()
        exit()
