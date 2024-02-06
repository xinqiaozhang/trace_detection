# %%
# use distilbert and a classification
import copy
import pickle
import os
import argparse
import numpy as np
from pathlib import Path
import torch.backends.cudnn as cudnn
import pdb

# %%
 

# %%
from sklearn.model_selection import cross_val_score, KFold
from sklearn import svm
from sklearn.metrics import mean_squared_error, auc, RocCurveDisplay
import iisignature
from einops import rearrange

import pickle as pkl
import xgboost as xgb
from einops import rearrange
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
from tqdm.contrib.concurrent import process_map

N=8

def find_files(directory, keywords):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if all(keyword in basename for keyword in keywords):
                filename = os.path.join(root, basename)
                return filename
    
    return 0

def accumulate_sig(sig, l, row):
    dt = max(1,int(row[0]))
    highest_1_bit = dt.bit_length()-1
    shift_factor = (N-(min(N,highest_1_bit)))
    frac = 1 << shift_factor
    sig[0][0] = frac
    # f_row = np.multiply(frac, row[1:]) 
    f_row = np.left_shift(row[1:], shift_factor)
    for level in range(1,l+1):
        sig[level] += np.right_shift(np.outer(sig[level-1],f_row).ravel(),N)

def calc_sig(data, d, l=4):
    sig = [
        np.array([0] * pow(d,x)) for x in range(l+1)
    ]
    sig[0][0] = 1
    for row in data:
        accumulate_sig(sig, l, row)    
    sig[0][0] = 1
    return sig

def get_windowed_lsigs(windowed_df, windowed_cycles, m):
    wlen = windowed_df.shape[1]
    num_channels = windowed_df.shape[2]
    # s = iisignature.prepare(num_channels, m)
    # llen = iisignature.logsiglength(num_channels, m)
    llen = 1
    for i in range(m):
        # Add the time channel
        llen += pow(num_channels, i + 1)
    # Preallocate outputs
    wlsigs_df = np.zeros((windowed_df.shape[0], llen), dtype=np.int32)
    
    nwindows = windowed_df.shape[0]
    for i in tqdm(range(nwindows)):
        window = windowed_df[i]
        cycles = pd.DataFrame(windowed_cycles[i], columns=['c'])

        # Clear NaNs and drop op
        df0 = pd.DataFrame(window, columns=['op', 'bm', 'cm', 'rb', 'rl', 'rs']).drop(columns='op')
        # df0.op = df0.op.fillna(0)
        df0 = df0.fillna(0)
        
        ## Compute First difference groups, and set basepoint to 0
        didx1 = cycles.diff()
        didx1.iloc[0] = 0
        # # Idea is to leverage cumsum and delta cycles in the first column
        df = pd.concat([didx1, df0], axis=1).astype(np.int32)
        # print(df)
        x = df.to_numpy(dtype=np.int32)
        # print(x)
        # lsig = iisignature.logsig(x, s)
        sig = calc_sig(x, x.shape[1], m)
        wlsigs_df[i] = np.concatenate(sig, dtype=np.int32)
    
    return wlsigs_df

def get_sig_worker(x):
    window, windowed_cycles, m = x
    cycles = pd.DataFrame(windowed_cycles, columns=['c'])

    # Clear NaNs and drop op
    df0 = pd.DataFrame(window, columns=['op', 'bm', 'cm', 'rb', 'rl', 'rs']).drop(columns='op')
    # df0.op = df0.op.fillna(0)
    df0 = df0.fillna(0)
        
    ## Compute First difference groups, and set basepoint to 0
    didx1 = cycles.diff()
    didx1.iloc[0] = 0
    # # Idea is to leverage cumsum and delta cycles in the first column
    # df = pd.concat([didx1, df0], axis=1).astype(np.int32)
    df = pd.concat([didx1, df0], axis=1).astype(np.int32) 
    # print("Tem hold here!!!!!!!!")
    # print(df)
    x = df.to_numpy(dtype=np.int32)
    sig = calc_sig(x, x.shape[1] - 1, m) # delta time is no longer included in the number of dimensions
    # return np.concatenate(sig, dtype=np.int32)
    return np.concatenate(sig) ## changed

def get_windowed_lsigs_parallel(windowed_df, windowed_cycles, m, num_workers=10):
    wlen = windowed_df.shape[1]
    num_channels = windowed_df.shape[2] - 1 # delta time is no longer included in the number of dimensions
    # s = iisignature.prepare(num_channels, m)
    # llen = iisignature.logsiglength(num_channels, m)
    llen = 1
    for i in range(m):
        # Add the time channel
        llen += pow(num_channels, i + 1)
    # Preallocate outputs
    wlsigs_df = np.zeros((windowed_df.shape[0], llen), dtype=np.int32)
    
    nwindows = windowed_df.shape[0]
    # Prep for parallel map
    wdf_rows = [row for row in windowed_df] # is actually a numpy array
    wc_rows = [row for row in windowed_cycles] # is actually a numpy array
    ms = [m for i in range(nwindows)]
    
    print("Mapping Feature extraction to %d workers" % num_workers)
    res = process_map(get_sig_worker, list(zip(wdf_rows, wc_rows, ms)), max_workers=num_workers, chunksize=100)
    print("Collecting results")
    for i in tqdm(range(nwindows)):
        wlsigs_df[i] = res[i]
    return wlsigs_df


def trace2windowed_lsigs(df, w, m):
    dft = rearrange(df.to_numpy()[:-(df.shape[0] % w)], '(w time) c -> w time c', time=w)
    cycles = rearrange(df.index.to_numpy()[:-(df.shape[0] % w)], '(w time) -> w time', time=w)
    return get_windowed_lsigs(dft, cycles, m)

def trace2windowed_lsigs_parallel(df, w, m):
    dft = rearrange(df.to_numpy()[:-(df.shape[0] % w)], '(w time) c -> w time c', time=w)
    cycles = rearrange(df.index.to_numpy()[:-(df.shape[0] % w)], '(w time) -> w time', time=w)
    return get_windowed_lsigs_parallel(dft, cycles, m)

def get_CWE_numbers(path):
    folder_names = []
    for name in os.listdir(path):
        if os.path.isdir(os.path.join(path, name)):
            folder_name = name.split('_')[0]
            folder_names.append(folder_name[3:])
    return folder_names

m = 3

UAF_category = ['_operator','_malloc_free','_new_delete_array','_new_delete','_return']
UAF_subcategory = [['_equals'],['_char_','_int_','_int64_','_long_','_struct'],['_char_','_int_','_int64_','_long_','_struct_','_class'],['_char_','_int_','_int64_','_long_','_struct_','_class_','_wchart'],['`_freed_ptr']]
# load_folder = "/data/xinqiao/akira/windowed_data_row/"
load_folder = "/data/xinqiao/akira/distilled_data/pkl_rui/"
# filename_num = 587663

# path_to_files = "/home/xinqiao/5-trojanai/akira-tcs/workloads/juliet/src/testcases/"
# CWE_list = get_CWE_numbers(path_to_files)
# CWE_list = ['121']
CWE_list = ['426']
distilled_folder = "/data/xinqiao/akira/distilled_data/"
for i in range(len(UAF_category)):
    for j in range(len(UAF_subcategory[i])):
        if i == 1 and j ==1 :
            continue
        filename_cat = UAF_category[i]
        filename_subcat = UAF_subcategory[i][j]

        if not os.path.exists(distilled_folder):
            os.makedirs(distilled_folder)

        for CWE in CWE_list:
            print("CWE is", CWE)
            if CWE == '416':
            # if 1:
                # CWE = None
                keywords_data = ['UAF', filename_cat, filename_subcat , '_data.pkl']
                keywords_label = ['UAF', filename_cat, filename_subcat ,'_labels.pkl']
                keywords_cycles = ['UAF', filename_cat, filename_subcat , '_cycles.pkl']
            else:
                keywords_data = ['CWE'+CWE, 'popen' ,'_data.pkl']
                keywords_label = ['CWE'+CWE, 'popen' ,'_labels.pkl']
                keywords_cycles = ['CWE'+CWE, 'popen' ,'_cycles.pkl']
            
            # for filename in find_files(save_folder, keywords_data):
            #     print(filename)
            # pdb.set_trace()
            print("using file", find_files(load_folder, keywords_data))
            print("using file", find_files(load_folder, keywords_label))
            print("using file", find_files(load_folder, keywords_cycles))
            
            if find_files(load_folder, keywords_data) == 0:
                continue
            
            with open(find_files(load_folder, keywords_data), "rb") as f: 
                BigTable = pickle.load(f)
            with open(find_files(load_folder, keywords_label), "rb") as f: 
                BigLabels = pickle.load(f)
            with open(find_files(load_folder, keywords_cycles), "rb") as f: 
                BigCycle = pickle.load(f)   
        if len(set(BigLabels)) < 2:
            print("filename_cat, filename_subcat is", filename_cat, filename_subcat)
            continue
        else:
            ###### process the labels
            windowed_lsigs = get_windowed_lsigs_parallel(BigTable, BigCycle, m, num_workers=15)
            #shape is (53697, 156)
            print("BigTable.shape is", BigTable.shape)
            print("windowed_lsigs.shape is", windowed_lsigs.shape)
            # pdb.set_trace()
            
            # keywords = filename_cat + filename_subcat
            keywords = str(CWE) + '_char_popen_'

            save_folder = "/data/xinqiao/akira/windowed_iisig/"
            with open(save_folder + "CWE" +keywords+"iisig_data.pkl", "wb") as fp:
                pickle.dump(windowed_lsigs, fp)
            with open(save_folder + "CWE" +keywords+"iisig_labels.pkl", "wb") as fp:
                pickle.dump(BigLabels, fp)
            raise ValueError("Done_stop here")
    

