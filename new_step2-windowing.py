
import sys
sys.path.append('/home/xinqiao/5-trojanai/akira-tcs/akira-ml/src')
from arctic import Arctic
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import re

from akira.datasets.AkiraDB import AkiraDB
from akira.datasets.DBTrace import DBTrace
from akira.datasets.pytorch.AkiraDataset import AkiraTraceWindowedIndexDataset, WindowingTransform
from akira.plotting.plot_trace import plot_from_windows

import torch
from torch.utils.data import DataLoader, Sampler, SubsetRandomSampler, BatchSampler
from torch import nn
from einops import rearrange
from tqdm import tqdm
import os
import logging
import pdb
# %%
# %config Application.log_level='ERROR'
# logging.basicConfig(level=logging.ERROR)
logging.getLogger('akira.feature_extraction.LabeledWindows').setLevel(logging.ERROR)

# %%
# Load the juliet runs
mongohost='127.0.0.1:27019'
engine = Arctic(mongohost)
db = AkiraDB(engine)
# %%
# engine.adminCommand({ getParameter: 1, storage: 1 })
# quota_in_bytes = 100 * 1024 * 1024 * 1024 * 1024
# TraceStore = 'traces'
# # engine.delete_library(TraceStore)
# db._engine.set_quota(TraceStore, quota_in_bytes)
# q2 = db._engine.get_quota(TraceStore)
# print("q2 is", q2)


# %%
symbols = db.list_symbols()
print(len(symbols))
# symbols
# pdb.set_trace()

# %%
# db.adminCommand({ getParameter: 1, storage: 1 })
# len(symbols)


def get_CWE_numbers(path):
    folder_names = []
    for name in os.listdir(path):
        if os.path.isdir(os.path.join(path, name)):
            folder_name = name.split('_')[0]
            folder_names.append(folder_name[3:])
    return folder_names

# pdb.set_trace()
path_to_files = "/home/xinqiao/5-trojanai/akira-tcs/workloads/juliet/src/testcases/"
CWE_list = get_CWE_numbers(path_to_files)
CWE_list = ['121']
for CWE in CWE_list:
    
    print(CWE)
    def MAKE_WORKLOAD(ID):
        return (int(CWE) << 4) | ID
    GOOD_WORKLOAD = MAKE_WORKLOAD(1)
    BAD_WORKLOAD    = MAKE_WORKLOAD(2)
    UNKNOWN         = 0
    label_map = {UNKNOWN: 0, GOOD_WORKLOAD: 1, BAD_WORKLOAD: 2}
    num_labels = len(label_map)
    
# CWE = 416
# def MAKE_WORKLOAD(ID):
#     return (CWE << 4) | ID

# MALLOC_WORKLOAD = MAKE_WORKLOAD(1)
# NEW_WORKLOAD    = MAKE_WORKLOAD(2)
# OK_USE_WORKLOAD = MAKE_WORKLOAD(3)
# FREE_WORKLOAD   = MAKE_WORKLOAD(4)
# DELETE_WORKLOAD = MAKE_WORKLOAD(5)
# UAF_WORKLOAD    = MAKE_WORKLOAD(6)
# UNKNOWN         = 0
# # Use this to index the label vector
# label_map = {UNKNOWN: 0, MALLOC_WORKLOAD: 1, NEW_WORKLOAD: 2, OK_USE_WORKLOAD: 3, FREE_WORKLOAD: 4, DELETE_WORKLOAD: 5, UAF_WORKLOAD: 6}
# num_labels = len(label_map)

# symbols = db.list_symbols()
# symbols_f = list(filter(lambda x: "all_" not in x.lower(), symbols))

# # symbols_f_good = list(filter(lambda x: "good" in x.lower(), symbols_f))
# # symbols_f_bad = list(filter(lambda x: "bad" in x.lower(), symbols_f))
# # symbols_f = list(filter(lambda x: "memory" in x.lower(), symbols))

# # symbols_f = symbols
# print(len(symbols_f))
# for s in symbols_f:
#     print(s)
# dummy_trace = db.read(symbols_f[0])
# tshape = dummy_trace.data_frame.shape
# print(tshape)
# print(dummy_trace.id)
# print(dummy_trace.read_metadata()['m5log'])


# %%
# dummy_trace.data_frame
# dummy_trace.labeled_windows
# print(dummy_trace.labels)
# print(dummy_trace.id)
# dummy_trace

# %%
    from bisect import bisect_right, bisect_left
    def find_le(a, x):
        'Find rightmost value less than or equal to x'
        i = bisect_right(a, x)
        if i:
            return i-1
        raise ValueError
    def index(a, x):
        'Locate the leftmost value exactly equal to x'
        i = bisect_left(a, x)
        if i != len(a) and a[i] == x:
            return i
        raise ValueError
    def find_gt(a, x):
        'Find leftmost value greater than x'
        i = bisect_right(a, x)
        if i != len(a):
            return i
        raise ValueError

    def find_ge(a, x):
        'Find leftmost item greater than or equal to x'
        i = bisect_left(a, x)
        if i != len(a):
            return i
        raise ValueError

    # UAF_category = ['_operator','_malloc_free','_new_delete_array','_new_delete','_return']
    # UAF_subcategory = [['_equals'],['_char_','_int_','_int64_','_long_','_struct'],['_char_','_int_','_int64_','_long_','_struct_','_class'],['_char_','_int_','_int64_','_long_','_struct_','_class_','_wchart'],['`_freed_ptr']]
        #  
    # UAF_category = ['_new_delete_array','_new_delete','_return']
    # UAF_subcategory = [['_long_','_struct_','_class'],['_char_','_int_','_int64_','_long_','_struct_','_class_','_wchart'],['`_freed_ptr']]
    # UAF_subcategory = [['_int64_t','_long_','_struct_','_class'],['_char_','_int_','_int64_','_long_','_struct_','_class_','_wchart']]

    # UAF_category = ['_return']
    # UAF_subcategory = [['_freed_ptr']]

    # UAF_category = ['_new_delete']
    # UAF_subcategory = [['_wchart']]

    # UAF_category = ['_new_delete_array']
    # UAF_subcategory = [['_int64_']]
        #  
        
    # for category_num in range(len(UAF_category)):
    #     choose_UAF_category = UAF_category[category_num]
    #     for subcategory_num in range(len(UAF_subcategory[category_num])):
    #         choose_UAF_subcategory = UAF_subcategory[category_num][subcategory_num]
    # category_num
    # UAF_subcategory =
    def juliet_filter(db: AkiraDB, symbol_list: list) -> list:
        def valid_run(trace):
            m5log = trace.read_metadata()['m5log']
            match = re.search("^m5> Finished .+?\(\)", m5log, re.MULTILINE)
            if match:
                return True
            else:
                return False              
        filtered_list = []
        # symbols_f
        for symbol in symbols:
            trace = db.read(symbol)
            if 'cwe'+CWE in trace.id.lower():
                print("INFO: Adding %s" % symbol)
                filtered_list.append(symbol)
        return filtered_list

    class WindowingLabelingTransform:
        """ 
        This class needs to return PyTorch Tensors
        """
        def __init__(self, window_width, label_threshold=0.6):
            self._w = window_width
            self._lthresh = label_threshold

        def get_labels(self, trace, bad=False):
            target_pid = 62
            df = trace.data_frame
            lw = trace.labeled_windows
            cycles = df.index.to_numpy()
            cycle_labels = np.zeros((len(cycles), num_labels))

            # For each labeled window, find it's start and end cycle -> set it's label vector
            for fw in lw:
                # Find the start,end indices of the window
                label = fw.label
                c_min = find_le(cycles, min(fw.range)) + 1
                c_max = find_le(cycles, max(fw.range))
                label_idx = label_map[label]
                cycle_labels[c_min:c_max, label_idx] = 1
            return cycle_labels
        
        def __call__(self, sample, fast=False):
            w = self._w                                                                                                                                        
            df = sample['df']
            trace = sample['trace']
            # Check if we should insert malicious labels
            bad = False
            if 'bad' in trace.id.lower():
                bad = True
            # Truncate shape to window boundaries
            dft = rearrange(df.to_numpy()[:-(df.shape[0] % w)], '(w time) c -> w time c', time=w)
            if fast:
                return {'df': dft, 'bad': bad}
            else:
                labels = self.get_labels(trace, bad=bad)
                cycles = df.index.to_numpy()
                labels_w = rearrange(labels[:-(labels.shape[0] % w)], '(w time) labels -> w time labels', time=w)
                cycles_w = rearrange(cycles[:-(cycles.shape[0] % w)], '(w time) -> w time', time=w)

                assert dft.shape[0] == labels_w.shape[0], "Label shape mismatch"

                # If enough of the labels in a window are bad then label that whole window
                # labels = np.zeros(labels_w.shape[0])
                threshs = np.sum(labels_w, axis=1) / labels_w.shape[1] # percent of bad windows
                # labels[threshs >= self._lthresh] = 1
                return {'df': dft, 'labels': threshs, 'bad': bad, 'cycles': cycles_w}

    window_width = 500
    dataset = AkiraTraceWindowedIndexDataset(mongohost, transform=WindowingLabelingTransform(window_width), symbol_filter=juliet_filter)
    print("total dataset length is: ", len(dataset))
    # Check for rough correctness
    # print("choose_UAF_category is: ", choose_UAF_category, "choose_UAF_subcategory is: ", choose_UAF_subcategory, "dataset length is: ", len(dataset))
    print("choose_CWE_category is: ", CWE)

    import pickle as pkl
    label_threshold=0.6
    # if reindex_labels:
        # Can use this info to help balance the datasets a bit
        # THIS IS ONLY VALID IF THE WINDOW SIZE HASNT CHANGED
    mal_indices = []
    for ii in tqdm(range(len(dataset))):
        # pdb.set_trace()
        sample = dataset[ii]
        label = sample['labels']
        uaf_percentage = label[label_map[BAD_WORKLOAD]]
        if uaf_percentage >= label_threshold:
            mal_indices.append(ii)
    print("length of mal_indices is",len(mal_indices))

    BigTable_1 = np.zeros((len(dataset), window_width, 6), dtype=np.float32)
    BigLabels_1 = np.zeros(len(dataset))
    BigCycles_1 = np.zeros((len(dataset), window_width))
    # len(dataset)
    # for i, idx in enumerate(range(len(dataset))):
    for i in range(len(dataset)):
        sample = dataset[i]
        BigTable_1[i] = sample['df']
        # BigLabels[i] = sample['labels']
        BigLabels_1[i] = 1 if i in mal_indices else 0
        BigCycles_1[i] = sample['cycles']
    filename_num = str(len(dataset))
    filename_cat = CWE
    # filename_subcat = choose_UAF_subcategory

    save_folder = "/data/xinqiao/akira/windowed_data_row/CWE"+CWE+"/"

    if not os.path.exists(save_folder):
        os.makedirs(save_folder)
        
    with open(save_folder+'CWE'+filename_cat+'_'+filename_num+"_data.pkl", "wb") as fp:
        pkl.dump(BigTable_1, fp)
    with open(save_folder+'CWE'+filename_cat+'_'+filename_num+"_labels.pkl", "wb") as fp:
        pkl.dump(BigLabels_1, fp)
    with open(save_folder+'CWE'+filename_cat+'_'+filename_num+"_cycles.pkl", "wb") as fp:
        pkl.dump(BigCycles_1, fp)
    print("INFO: Saved data to", save_folder,filename_num,filename_cat)
    # %%
