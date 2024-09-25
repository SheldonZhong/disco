#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import matplotlib.pyplot as mpl
from matplotlib import ticker
import numpy as np
import sys
import os

# common
workloads = ['A', 'B', 'C', 'E', 'F']

hatch_map = {
    'DiscoDB' : '',
    'RemixDB' : '\\\\',
    'RocksDB' : '//',
    'Full-Index' : 'o',
    'No-Index' : '*',
}

label_mappings = {
    'RemixDB' : 'remixdb',
    'DiscoDB' : 'discodb',
    'RocksDB' : 'rdb',
    'Full-Index' : 'full',
    'No-Index' : 'dummy',
}

bar_order = ['DiscoDB', 'RemixDB', 'RocksDB', 'Full-Index', 'No-Index']

color_map = {
    'RocksDB' : '#F8FFE5',
    'DiscoDB' : '#06D6A0',
    'RemixDB' : '#1B9AAA',
    'Full-Index' : '#EF476F',
    'No-Index' : '#FFC43D',
}

headers = ['sysname', 'workload', 'mem', 'klen', 'vlen', 'rgen', 'nsec', 'nops', 'ops',
           'nset', 'nupd', 'nget', 'nscan']

mpl.subplots_adjust(wspace=0)
def plot_ycsb(rdf):
    fig = mpl.figure(layout='constrained', figsize=(8, 2))
    gs = fig.add_gridspec(nrows=1, ncols=2, width_ratios=[6, 1])

    ax = fig.add_subplot(gs[0, 0])

    x = np.arange(len(workloads))
    width = 0.15
    multiplier = 0

    for idx, sysname in enumerate(bar_order):
        wdf = rdf[rdf['sysname'] == label_mappings[sysname]]
        offset = width * multiplier
        bars = []
        for workload in workloads:
            tdf = wdf[wdf['workload'] == 'YCSB-{}'.format(workload)]
            if len(tdf) != 1:
                print(tdf.shape, len(tdf))
            bars.append(tdf['ops'].iloc[0])

        rects = ax.bar(x + offset, np.array(bars) / 1e3, width,
                       label=sysname,
                       hatch=hatch_map[sysname],
                       edgecolor='black',
                       color=color_map[sysname])
        multiplier += 1

    ax1 = fig.add_subplot(gs[0, 1])
    ax1.set_yticks([])
    ax2 = ax1.twinx()

    multiplier = 0
    for idx, sysname in enumerate(bar_order):
        wdf = rdf[rdf['sysname'] == label_mappings[sysname]]
        offset = width * multiplier
        bars = []
        tdf = wdf[wdf['workload'] == 'YCSB-D']
        if len(tdf) != 1:
            print(tdf.shape, len(tdf))
        bars.append(tdf['ops'].iloc[0])

        rects = ax2.bar(x[-1] + 1 + offset, np.array(bars) / 1e6, width,
                       label=sysname,
                       hatch=hatch_map[sysname],
                       edgecolor='black',
                       color=color_map[sysname])
        multiplier += 1

    ax.set_xticks(x + 2 * width, workloads)
    ax.set_ylabel('Throughput (KOPS)')
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper center', ncol=5, bbox_to_anchor=(0.5, 1.17), fontsize=11)
    ax.grid(True, axis='y', ls='--')
    ax.set_axisbelow(True)

    ax2.set_ylabel('Throughput (MOPS)')
    ax2.set_xticks([x[-1] + 1 + 2 * width], ['D'])
    ax2.grid(True, axis='y', ls='--')
    ax2.set_axisbelow(True)
    return ax, fig


if __name__ == '__main__':
    os.makedirs("figs", exist_ok=True)

    if len(sys.argv) < 2:
        print(sys.argv[0], "<ycsb_csv>")
        sys.exit(1)

    df = pd.read_csv(sys.argv[1], names=headers)


    ax, fig = plot_ycsb(df)
    fig.savefig("figs/ycsb_16g.pdf", bbox_inches="tight", pad_inches=0.03, format='pdf')
