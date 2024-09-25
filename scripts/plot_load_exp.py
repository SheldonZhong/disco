#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import matplotlib.pyplot as mpl
from matplotlib import ticker
import numpy as np
import sys
import os

# common
label_mappings = {
    'RemixDB' : 'remixdb',
    'DiscoDB' : 'discodb',
    'RocksDB' : 'rdb',
    'Full-Index' : 'full',
    'No-Index' : 'dummy',
}

bar_order = ['DiscoDB', 'RemixDB', 'RocksDB', 'Full-Index', 'No-Index']

memory = ['16G', '32G', '64G']
mem_hatch_map = {
    '16G' : '',
    '32G' : '\\\\',
    '64G' : '//',
    '128G' : '*',
}

headers = ['sysname', 'mem', 'klen', 'vlen', 'thread', 'nkv', 'rgen', 'verb', 'nsec', 'num_ops', 'ops',
          'bio_write_io', 'bio_read_io', 'bio_write_bytes', 'bio_read_bytes',
           'stats_write_io', 'stats_read_io', 'stats_write_sectors', 'stats_read_sectors',
           'sctl_write_io', 'sctl_read_io', 'sctl_write_bytes', 'sctl_read_bytes']

os.makedirs("figs", exist_ok=True)

if len(sys.argv) < 2:
    print(sys.argv[0], "<loading_exp_csv>")
    sys.exit(1)

df = pd.read_csv(sys.argv[1], names=headers)

wdf = df

groups = np.arange(len(bar_order))
width = 0.20
multiplier = 0

fig = mpl.figure(layout='constrained', figsize=(5, 1.7))
gs = fig.add_gridspec(nrows=1, ncols=1)
ax = fig.add_subplot(gs[0, 0])

for mem in memory:
    rdf = wdf[wdf['mem'] == mem]
    offset = width * multiplier
    bars = []
    for bar in bar_order:
        row = rdf[rdf['sysname'] == label_mappings[bar]]
        if len(row) != 1:
            print(row.shape, len(row))
        ops = row['ops'].iloc[0] / 1000
        print(ops, bar, mem)
        bars.append(ops)
    rects = ax.bar(groups + offset, bars, width, label=mem,
                   hatch=mem_hatch_map[mem], edgecolor='black')
    multiplier += 1

ax.yaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.0f}"))
ax.set_xticks(groups + width, bar_order)
ax.set_ylabel('Throughput (KOPS)')
ax.legend(loc='best', ncols=3)
ax.set_yticks(np.arange(0, 400, 50), minor=True)
ax.set_axisbelow(True)
ax.grid(axis='y', color='gray', linestyle='dashed', which='both')
fig.savefig("figs/load_thruput.pdf", bbox_inches="tight", pad_inches=0.03, format='pdf')


groups = np.arange(len(label_mappings))
width = 0.2
multiplier = 0

fig = mpl.figure(layout='constrained', figsize=(8, 1.7))
gs = fig.add_gridspec(1, 2)
ax1 = fig.add_subplot(gs[0, 0])
ax2 = fig.add_subplot(gs[0, 1])


for mem in memory:
    rdf = wdf[wdf['mem'] == mem]
    offset = width * multiplier
    wbars = []
    rbars = []
    for bar in bar_order:
        row = rdf[rdf['sysname'] == label_mappings[bar]]
        if len(row) != 1:
            print(row.shape, len(row))
        wops = row['bio_write_bytes'].iloc[0] / 1024 / 1024 / 1024 / 1024
        rops = row['bio_read_bytes'].iloc[0] / 1024 / 1024 / 1024 / 1024
        wbars.append(wops)
        rbars.append(rops)
    rects = ax1.bar(groups + offset, wbars, width, label=mem,
                   hatch=mem_hatch_map[mem], edgecolor='black')

    rects = ax2.bar(groups + offset, rbars, width, label=mem,
                   hatch=mem_hatch_map[mem], edgecolor='black')

    multiplier += 1

ax1.yaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.1f}"))
ax2.yaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.1f}"))
ax1.set_xticks(groups + width, bar_order)
ax2.set_xticks(groups + width, bar_order)
ax1.set_title('Total Write I/O')
ax2.set_title('Total Read I/O')
ax1.set_ylabel('Total I/O (TB)')
ax1.legend(ncols=1)
# ax1.set_ylim(0, 1.6)
# ax1.set_yticks(np.arange(0, 2, 0.5))
# ax1.set_yticks(np.arange(0, 1.5, 0.25), minor=True)
# ax2.set_yticks(np.arange(0, 2.5, 0.5))
ax1.set_axisbelow(True)
ax2.set_axisbelow(True)
ax1.grid(axis='y', color='gray', linestyle='dashed', which='both')
ax2.grid(axis='y', color='gray', linestyle='dashed')
fig.savefig("figs/load_io.pdf", bbox_inches="tight", pad_inches=0.03, format='pdf')

