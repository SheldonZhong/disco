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

label_formatter = '{:,.0f}'

headers = ['sysname', 'mem', 'klen', 'vlen', 'thread', 'nkv', 'rgen', 'verb', 'nsec', 'num_ops', 'ops',
          'bio_write_io', 'bio_read_io', 'bio_write_bytes', 'bio_read_bytes',
           'stats_write_io', 'stats_read_io', 'stats_write_sectors', 'stats_read_sectors',
           'sctl_write_io', 'sctl_read_io', 'sctl_write_bytes', 'sctl_read_bytes']

def plot_read(wdf):
    groups = np.arange(len(bar_order))
    width = 0.25

    fig = mpl.figure(layout='constrained', figsize=(5, 1.7))
    gs = fig.add_gridspec(nrows=1, ncols=1)
    multiplier = 0

    multiplier = 0

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
            bars.append(ops)
            print(ops, mem, bar)
        rects = ax.bar(groups + offset, bars, width, label=mem,
                       hatch=mem_hatch_map[mem], edgecolor='black')
        ax.bar_label(rects, padding=1, fmt=label_formatter)
        multiplier += 1

    ax.yaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.0f}"))
    ax.set_xticks(groups + width, bar_order, fontsize=9)
    ax.set_ylabel('Throughput (KOPS)')
    ax.legend(loc='upper right', ncols=1)
    ax.set_axisbelow(True)
    ax.grid(axis='y', color='gray', linestyle='dashed')

    return ax, fig

def plot_read_io(wdf):
    groups = np.arange(len(label_mappings))
    width = 0.25
    multiplier = 0

    fig = mpl.figure(layout='constrained', figsize=(5, 1.7))
    gs = fig.add_gridspec(1, 1)
    ax = fig.add_subplot(gs[0, 0])

    for mem in memory:
        rdf = wdf[wdf['mem'] == mem]
        offset = width * multiplier
        bars = []
        for bar in bar_order:
            row = rdf[rdf['sysname'] == label_mappings[bar]]
            if len(row) != 1:
                    print(row.shape, len(row))
            row
            read_io = row['bio_read_bytes'].iloc[0]
            nops = rdf[rdf['sysname'] == label_mappings[bar]]['num_ops'].iloc[0]
            bars.append(read_io / nops / 1024)
        rects = ax.bar(groups + offset, bars, width, label=mem,
                       hatch=mem_hatch_map[mem], edgecolor='black')
        ax.bar_label(rects, padding=1, fmt=label_formatter)
        multiplier += 1

    ax.yaxis.set_major_formatter(ticker.StrMethodFormatter("{x:,.0f}"))
    ax.set_xticks(groups + width, bar_order)
    ax.set_ylabel('I/O per query (KB)')
    ax.legend(loc='upper left', ncols=1)
    ax.set_axisbelow(True)
    ax.grid(axis='y', color='gray', linestyle='dashed')

    return ax, fig

if __name__ == '__main__':
    os.makedirs("figs", exist_ok=True)

    if len(sys.argv) < 2:
        print(sys.argv[0], "<read_exp_csv>")
        sys.exit(1)

    df = pd.read_csv(sys.argv[1], names=headers)


    ax, fig = plot_read(df[(df['rgen'] == 'uniform') & (df['thread'] == 4) & (df['verb'] == 'seeknext')])
    # ax.set_yticks(np.arange(0, 50, 10))
    # ax.set_ylim((0, 45))
    fig.savefig("figs/dbbench_uniform_read_thruput.pdf", bbox_inches="tight", pad_inches=0.03, format='pdf')


    ax, fig = plot_read(df[(df['rgen'] == 'unizipf') & (df['thread'] == 4) & (df['verb'] == 'seeknext')])
    # ax.set_yticks(np.arange(0, 60, ))
    # ax.set_ylim((0, 220))
    fig.savefig("figs/dbbench_unizipf_read_thruput.pdf", bbox_inches="tight", pad_inches=0.03, format='pdf')


    ax, fig = plot_read(df[(df['rgen'] == 'uniform') & (df['thread'] == 4) & (df['verb'] == 'pro')])
    # ax.set_yticks(np.arange(0, 50, 10))
    # ax.set_ylim((0, 48))
    fig.savefig("figs/dbbench_uniform_point_read_thruput.pdf", bbox_inches="tight", pad_inches=0.03, format='pdf')


    ax, fig = plot_read_io(df[(df['rgen'] == 'uniform') & (df['thread'] == 1) & (df['verb'] == 'seeknext')])
    # ax.set_yticks(np.arange(0, 30, 5))
    # ax.set_ylim(0, 29)
    fig.savefig("figs/dbbench_uniform_read_io.pdf", bbox_inches="tight", pad_inches=0.03, format='pdf')

