


# %%
# use distilbert and a classification
import copy
import pickle
import os
# import argparse
import numpy as np
# from pathlib import Path
# import torch.backends.cudnn as cudnn
import pdb
import sklearn
import warnings

# Ignore specific warning related to precision loss in ecod.py
warnings.filterwarnings("ignore", message="Precision loss occurred in moment calculation due to catastrophic cancellation.*")
from tqdm import tqdm
import os
import glob
import numpy as np
from pyod.models.ecod import ECOD
import matplotlib.pyplot as plt
from pyod.models.thresholds import FILTER
import time

def get_CWE_numbers(path):
    folder_names = []
    for name in os.listdir(path):
        if os.path.isdir(os.path.join(path, name)):
            folder_name = name.split('_')[0]
            folder_names.append(folder_name[3:])
    return folder_names

def save_to_file(distilled_path, X_outlier, X_train, interesting_label, common_label,data_metrix = None):
    with open(distilled_path+"_iisig_interesting_data.pkl", "wb") as fp:
        pickle.dump(X_outlier, fp)
    with open(distilled_path+"_iisig_common_data.pkl", "wb") as fp:
        pickle.dump(X_train, fp)
    with open(distilled_path+"_iisig_interesting_labels.pkl", "wb") as fp:
        pickle.dump(interesting_label, fp)    
    with open(distilled_path+"_iisig_common_labels.pkl", "wb") as fp:
        pickle.dump(common_label, fp) 
    # with open(distilled_path+"_metrix.txt", "wb") as fp:
    #     pickle.dump(data_metrix, fp) 

# UAF_category = ['_operator','_malloc_free','_new_delete_array','_new_delete','_return']
# UAF_subcategory = [['_equals'],['_char_','_int_','_int64_','_long_','_struct'],['_char_','_int_','_int64_','_long_','_struct_','_class'],['_char_','_int_','_int64_','_long_','_struct_','_class_','_wchart'],['`_freed_ptr']]
# load_folder = "/data/xinqiao/akira/windowed_data_row/"
# # filename_num = 587663

# path_to_files = "/home/xinqiao/5-trojanai/akira-tcs/workloads/juliet/src/testcases/"
# CWE_list = get_CWE_numbers(path_to_files)
# # CWE_list = ['121']
# CWE_list = ['416']
# distilled_folder = "/data/xinqiao/akira/distilled_data/"

UAF_category = ['_operator','_malloc_free','_new_delete_array','_new_delete','_return']
UAF_subcategory = [['_equals'],['_char_','_int_','_int64_','_long_','_struct'],['_char_','_int_','_int64_','_long_','_struct_','_class'],['_char_','_int_','_int64_','_long_','_struct_','_class_','_wchart'],['`_freed_ptr']]
load_folder = "/data/xinqiao/akira/windowed_data_row/"
# filename_num = 587663

path_to_files = "/home/xinqiao/5-trojanai/akira-tcs/workloads/juliet/src/testcases/"
CWE_list = get_CWE_numbers(path_to_files)
# CWE_list = ['121']
CWE_list = ['416']
distilled_folder = "/data/xinqiao/akira/distilled_data/"
save_folder = "/data/xinqiao/akira/windowed_iisig/pkl/"
# for i in range(len(UAF_category)):
#     for j in range(len(UAF_subcategory[i])):
for tem_batch_size in [3000,1000,500,300,100]:
    if 1:
        if 1:
    # for i in range(1,len(UAF_category)):
    #     for j in range(len(UAF_subcategory[i])):
            i = 1; j= 1
            # tem_batch_size = 1000
            # if i == 0:
            #     continue
            filename_cat = UAF_category[i]
            filename_subcat = UAF_subcategory[i][j]

            if not os.path.exists(distilled_folder):
                os.makedirs(distilled_folder)

            keywords = filename_cat + filename_subcat
            # if keywords == "_malloc_free_char_":
            #     continue
            # if keywords == "_char_popen_":
            #     continue
            # keywords = "426_char_popen_"
            # keywords = "426_char_system_"
            print("keywords", keywords)
            # if keywords != "_new_delete_int_":
            #     continue
            # CWE426_char_popen_cycles.pkl
            try:
                with open(save_folder + "CWE" +keywords+"iisig_data.pkl", "rb") as f: 
                        raw_iisig_data = pickle.load(f)
                with open(save_folder + "CWE" +keywords+"iisig_labels.pkl", "rb") as f: 
                        raw_iisig_labels = pickle.load(f)
            # pdb.set_trace()
            # try:
            #     with open(save_folder + "CWE" +keywords+"data.pkl", "rb") as f: 
            #             iisig_data = pickle.load(f)
            #     with open(save_folder + "CWE" +keywords+"labels.pkl", "rb") as f: 
            #             iisig_labels = pickle.load(f)
            except:
                print("keywords", keywords, "not found")
                continue
            # pdb.set_trace()
            # assert np.unique(iisig_labels).shape[0] == 2
            # pdb.set_trace()
            if np.unique(raw_iisig_labels).shape[0] != 2:
                print("no label =1 data, skip....")
                continue
            pdb.set_trace()
             # raw_iisig_data
            # raw_iisig_labels
            ### add distillation
            initial_percent = 0.1
            batch_size = tem_batch_size
            print("batch_size is ", batch_size)
            clf2 = ECOD()
            record_time = 0

           
            
            
            tem_data_length = len(iisig_data)
            initial_length = int(initial_percent * tem_data_length)

            data_initial = iisig_data[:initial_length, :]
            common_label = iisig_labels[:initial_length]
            interesting_label = []

            data_extra = iisig_data[initial_length:, :]
            labels_extra = iisig_labels[initial_length:]
            if len(iisig_data) != len(iisig_labels):
                print("length of iisig_data is ", len(iisig_data))
                print("length of iisig_labels is ", len(iisig_labels))
                print("length of data_extra is ", len(data_extra))
                continue

            print("length of labels_extra is ", len(labels_extra))

            X_train = data_initial
            X_outlier = []
            X_buffer = []
            common_label_buffer = []
            buffer_count = 0
            buffer_max = int(tem_batch_size/3)

            clf2.fit(X_train)

            for x in tqdm(range(int(np.floor(len(data_extra) / batch_size)))):
                t1 = time.time()
                X_test = data_extra[x * batch_size:(x + 1) * batch_size]
                y_test = labels_extra[x * batch_size:(x + 1) * batch_size]
                # pdb.set_trace()
                if buffer_count > buffer_max:
                    X_buffer = np.concatenate(X_buffer, axis=0)
                    X_train = np.concatenate((X_train, X_buffer), axis=0)
                    clf2.fit(X_train)
                    buffer_count = 0
                    X_buffer = []

                if record_time:
                    t2 = time.time()
                    print("stage 1 time usage:", t2 - t1)

                y_test_scores = clf2.decision_function(X_test)

                if record_time:
                    t3 = time.time()
                    print("stage 2 time usage:", t3 - t2)

                thres = FILTER()
                labels = thres.eval(y_test_scores)

                if record_time:
                    t4 = time.time()
                    print("stage 3 time usage:", t4 - t3)

                if x == 0:
                    X_outlier = X_test[labels == 1]
                    interesting_label = y_test[labels == 1]
                else:
                    X_outlier = np.concatenate((X_outlier, X_test[labels == 1]), axis=0)
                    # pdb.set_trace()
                    interesting_label = np.concatenate((interesting_label.reshape(-1), y_test[labels == 1].reshape(-1)), axis=0)
                # np.concatenate((interesting_label.reshape(-1), []].reshape(-1)), axis=0)
                # X_outlier.append(X_test[labels == 1])
                # pdb.set_trace()
                # interesting_label.append(y_test[labels == 1])

                X_buffer.append(X_test[labels == 0])
                common_label_buffer.append(y_test[labels == 0])

                buffer_count += len(X_test[labels == 0])

            if X_buffer != []:
                # pdb.set_trace()
                X_buffer = np.concatenate(X_buffer, axis=0)
                X_train = np.concatenate((X_train, X_buffer), axis=0)
                # pdb.set_trace()
                common_label = np.concatenate((common_label, np.concatenate(common_label_buffer).reshape(-1)), axis=0)
                
                            # if save:
                        #     if X_outlier != []: 
            #         X_outlier = np.concatenate(X_outlier, axis=0)
            #     save_path = './processed_LTP_v' + str(version) + '/' 
            #     np.save(save_path + 'processed_batch1_'+str(batch_size)+'_buffer_size_'+str(buffer_max)+'_'+file_name, X_train)
                #     np.save(save_path + 'interesting_processed_batch1_'+str(batch_size)+'_buffer_size_'+str(buffer_max)+'_'+file_name, X_outlier)

            
                # plot the data
            plot = 0
            if plot:
                fig, axis = plt.subplots(1,3, figsize=(18, 6))
                y_org_score = clf2.decision_function(tem_data)
                y_normal_scores = clf2.decision_function(X_train)
                y_outlier_scores = clf2.decision_function(X_outlier)
                
                axis[0].hist(y_org_score,bins=50, alpha=0.5)
                axis[1].hist(y_normal_scores,bins=50, alpha=0.5)
                axis[2].hist(y_outlier_scores,bins=50, alpha=0.5)
                hist, bins = np.histogram(y_test_scores, bins='auto')
                max_bin_index = np.argmax(hist)
                max_bin_value = hist[max_bin_index]
                one_way_offset = max(max(y_test_scores)-max_bin_value,max_bin_value - min(y_test_scores))
                # max_bin_center = (bins[max_bin_index] + bins[max_bin_index + 1]) / 2
                yabs_mean = (max(y_test_scores)- min(y_test_scores))/2
                
                axis[0].set_xlim(max_bin_value-one_way_offset, max_bin_value + one_way_offset)
                axis[1].set_xlim(max_bin_value-one_way_offset, max_bin_value + one_way_offset)
                axis[2].set_xlim(max_bin_value-one_way_offset, max_bin_value + one_way_offset)
                
                axis[0].title.set_text("# of data in origional plot: "+ str(len(tem_data)))
                axis[1].title.set_text("# of normal data in processed plot: "+ str(len(y_normal_scores)))
                axis[2].title.set_text("# of outlier data in processed plot: "+ str(len(y_outlier_scores)))

                fig.savefig(save_path + 'processed_'+file_name +'batch_'+str(batch_size)+'_buffer_size_'+str(buffer_max)+'.png')
            save = 1
            if save:
                if np.unique(interesting_label).shape[0] != 2:
                    print("no label =1 data, skip....")
                    continue
                # data_metrix = sklearn.metrics.roc_auc_score(np.zeros_like(common_label), common_label)
                # pdb.set_trace()
                # save_to_file(distilled_folder + "CWE" +keywords+"_batch_"+str(batch_size),X_outlier, X_train, interesting_label, common_label)
                # if np.unique(common_label).shape[0] != 2:
                #     print("no label =1 data for common label, skip....")
                    # continue
                save_to_file(distilled_folder + "CWE" +keywords+"_batch_"+str(batch_size),X_outlier, X_train, interesting_label, common_label)
                print("saved to file") 
                # if save :
                        # save_folder = "/data/xinqiao/akira/windowed_iisig/"
                    # assert np.unique(interesting_label).shape[0] == 2
                
                
                  
                 
            
# %%
#
        # with open(distilled_folder + "CWE" +keywords+"iisig_labels.pkl", "wb") as fp:
        #     pickle.dump(BigLabels, fp)