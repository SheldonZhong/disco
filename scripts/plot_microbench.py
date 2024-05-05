#!/usr/bin/env python
# coding: utf-8

import pandas as pd
import matplotlib.pyplot as mpl
import matplotlib
matplotlib.rc('pdf', fonttype=42)
import configparser
import glob
import numpy as np

import argparse

parser = argparse.ArgumentParser();
parser.add_argument("result_prefix")
args = parser.parse_args()


color_map = {
    'b+-tree' : '#1f77b4',
    'lsm-tree-probe' : '#ff7f0e',
    'lsm-tree-seek' : '#2ca02c',
    'disco' : '#e377c2',
    'remix' : '#17becf',
}

marker_map = {
    'b+-tree' : '*',
    'lsm-tree-probe' : 'o',
    'lsm-tree-seek' : 'o',
    'disco' : 'x',
    'remix' : '^',
}

folder_names = []
folder_names.append(args.result_prefix)

config_list = []
for folder_name in folder_names:
    for name in glob.glob(f'{folder_name}/*.meta'):
        with open(name, 'r') as f:
            config_string = '[top]\n' + f.read()
            config = configparser.ConfigParser()
            config.read_string(config_string)
            config_list.append(config['top'])

meta_df = pd.DataFrame.from_dict(config_list)

# configparser only loads string types, convert them to numeric when possible
for key in meta_df.keys():
    try:
        meta_df[key] = pd.to_numeric(meta_df[key])
    except:
        pass

csv_df_list = []
for folder_name in folder_names:
    csv_df = pd.read_csv(f'{folder_name}.csv',
            names=['filename', 'cap', 'miss_count', 'hit_count', 'tot_access'])
    csv_df_list.append(csv_df)

csv_df = pd.concat(csv_df_list, axis=0, ignore_index=True)

df = csv_df.set_index('filename').join(meta_df.set_index('trace_file'))


# introduction motivation part
wdf = df[df['mode'] == 'mixed']
wdf = wdf[wdf['rgen'] == 'uniform']

fig = mpl.figure(constrained_layout=True, figsize=(5.8, 2))
gs = fig.add_gridspec(1, 1)
ax = fig.add_subplot(gs[0, 0])

mark_at = 16

# no bloom
sysname = 'lsm-tree-seek'
rdf = wdf[wdf['nway'] == 8]
rdf = rdf[rdf['operation'] == 'seek']
rdf = rdf[rdf['fs_name'] == 'mbtx']
rdf = rdf[rdf['bt_bloom'] == 'false']
rdf = rdf[rdf['leaf_bloom'] == 'false']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'LSM-tree, seek', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname],
        linestyle='--')


# bloom
sysname = 'lsm-tree-probe'
rdf = wdf[wdf['nway'] == 8]
rdf = rdf[rdf['operation'] == 'probe']
rdf = rdf[rdf['fs_name'] == 'mbtx']
rdf = rdf[rdf['bt_bloom'] == 'true']
rdf = rdf[rdf['leaf_bloom'] == 'false']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'LSM-tree, probe', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname]
        )

# no bloom
sysname = 'b+-tree'
rdf = wdf[wdf['nway'] == 1]
rdf = rdf[rdf['operation'] == 'probe']
rdf = rdf[rdf['fs_name'] == 'mbtx']
rdf = rdf[rdf['bt_bloom'] == 'false']
rdf = rdf[rdf['leaf_bloom'] == 'false']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'B$^+$-tree, probe / seek', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname]
        )

ax.set_xscale('log', base=10)
ax.set_xlabel('Cache to data size ratio')

ax.set_yticks([4 * i for i in range(0, 10)])
ax.set_yticks([2 * i for i in range(0, 10)], minor=True)

ax.set_ylim((0, 18))
ax.set_xlim((2 ** 5 / 2 ** 16, 2 ** 16 / 2 ** 16))
ax.set_ylabel('I/Os per Query')
ax.legend()
ax.grid(ls='--', which='both', axis='y')
ax.grid(ls='--', which='major', axis='x')

fig.savefig("intro-exp.pdf", bbox_inches="tight", pad_inches=0.03, format='pdf')


wdf = df[df['nway'] == 8]
wdf = wdf[wdf['mode'] == 'mixed']
wdf = wdf[wdf['operation'] == 'seek']
wdf = wdf[wdf['rgen'] == 'uniform']

mark_at = 16

fig = mpl.figure(constrained_layout=True, figsize=(5.8,2))
gs = fig.add_gridspec(1, 1)
ax = fig.add_subplot(gs[0, 0])

# no bloom
sysname = 'lsm-tree-seek'
rdf = wdf[wdf['fs_name'] == 'mbtx']
rdf = rdf[rdf['bt_bloom'] == 'false']
rdf = rdf[rdf['leaf_bloom'] == 'false']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'LSM-tree', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname],
        linestyle='--'
        )

# remix
sysname = 'remix'
rdf = wdf[wdf['fs_name'] == 'bt_rc']
rdf = rdf[rdf['dbits'] == 'false']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'REMIX', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname]
        )

# disco
sysname = 'disco'
rdf = wdf[wdf['fs_name'] == 'bt_rc']
rdf = rdf[rdf['dbits'] == 'true']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'Disco', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname]
        )

# no bloom
sysname = 'b+-tree'
wdf = df[df['nway'] == 1]
wdf = wdf[wdf['mode'] == 'mixed']
wdf = wdf[wdf['operation'] == 'seek']
rdf = wdf[wdf['rgen'] == 'uniform']
rdf = rdf[rdf['fs_name'] == 'mbtx']
rdf = rdf[rdf['bt_bloom'] == 'false']
rdf = rdf[rdf['leaf_bloom'] == 'false']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'B$^+$-tree', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname]
        )

ax.set_xscale('log', base=10)
ax.set_xlabel('Cache to data size ratio')

ax.set_yticks([4 * i for i in range(0, 10)])
ax.set_yticks([2 * i for i in range(0, 10)], minor=True)

ax.set_ylim((0, 18))
ax.set_xlim((2 ** 5 / 2 ** 16, 2 ** 16 / 2 ** 16))
ax.set_ylabel('I/Os per Query')
ax.legend()

ax.grid(ls='--', which='both', axis='y')
ax.grid(ls='--', which='major', axis='x')

fig.savefig("eval_seek_8.pdf", bbox_inches="tight",
             pad_inches=0.03, format='pdf')


wdf = df[df['nway'] == 8]
wdf = wdf[wdf['mode'] == 'mixed']
wdf = wdf[wdf['operation'] == 'probe']
wdf = wdf[wdf['rgen'] == 'uniform']

mark_at = 16

fig = mpl.figure(constrained_layout=True, figsize=(5.8,2))
gs = fig.add_gridspec(1, 1)
ax = fig.add_subplot(gs[0, 0])

# bloom
sysname = 'lsm-tree-probe'
rdf = wdf[wdf['fs_name'] == 'mbtx']
rdf = rdf[rdf['bt_bloom'] == 'true']
rdf = rdf[rdf['leaf_bloom'] == 'false']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'LSM-tree', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname])

# remix
sysname = 'remix'
rdf = wdf[wdf['fs_name'] == 'bt_rc']
rdf = rdf[rdf['dbits'] == 'false']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'REMIX', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname])

# disco
sysname = 'disco'
rdf = wdf[wdf['fs_name'] == 'bt_rc']
rdf = rdf[rdf['dbits'] == 'true']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'Disco', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname])

# no bloom
# rdf = wdf[wdf['fs_name'] == 'mbtx']
# rdf = rdf[rdf['bt_bloom'] == 'false']
# rdf = rdf[rdf['leaf_bloom'] == 'false']
# rdf = rdf.sort_values('cap')
# iopq = rdf['miss_count'] / rdf['num_ops']
# if len(rdf) != 112:
#     print("length of rdf is not 112")
# ax.plot(rdf['cap'] / (2 ** 16), iopq, label=f'Runs w.o. BF',
#        markevery=mark_at, marker='^')

# B+-tree
sysname = 'b+-tree'
wdf = df[df['mode'] == 'mixed']
wdf = wdf[wdf['rgen'] == 'uniform']
rdf = wdf[wdf['nway'] == 1]
rdf = rdf[rdf['operation'] == 'probe']
rdf = rdf[rdf['fs_name'] == 'mbtx']
rdf = rdf[rdf['bt_bloom'] == 'false']
rdf = rdf[rdf['leaf_bloom'] == 'false']
rdf = rdf.sort_values('cap')
iopq = rdf['miss_count'] / rdf['num_ops']
if len(rdf) != 112:
    print("length of rdf is not 112")
ax.plot(rdf['cap'] / (2 ** 16), iopq,
        label=f'B$^+$-tree', markevery=mark_at,
        marker=marker_map[sysname], color=color_map[sysname])

ax.set_xscale('log', base=10)
ax.set_xlabel('Cache to data size ratio')

ax.set_yticks([4 * i for i in range(0, 10)])
ax.set_yticks([2 * i for i in range(0, 10)], minor=True)
ax.set_ylim((0, 18))

ax.set_xlim((2 ** 5 / 2 ** 16, 2 ** 16 / 2 ** 16))
ax.set_ylabel('I/Os per Query')

ax.legend()

ax.grid(ls='--', which='both', axis='y')
ax.grid(ls='--', which='major', axis='x')

fig.savefig("eval_probe_8_mixed.pdf", bbox_inches="tight",
             pad_inches=0.03, format='pdf')

