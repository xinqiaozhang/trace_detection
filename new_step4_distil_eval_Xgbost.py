
import numpy as np
import glob
import os
import glob
import numpy as np
from sklearn.manifold import TSNE
import matplotlib.pyplot as plt
# from sklearn.cluster import KMeans
# from sklearn.decomposition import PCA

import xgboost as xgb
from sklearn.model_selection import cross_val_score, KFold
# from sklearn import svm
from sklearn.metrics import mean_squared_error, auc, RocCurveDisplay
import glob
import os
import pickle
import pdb

# %%
def get_CWE_numbers(path):
    folder_names = []
    for name in os.listdir(path):
        if os.path.isdir(os.path.join(path, name)):
            folder_name = name.split('_')[0]
            folder_names.append(folder_name[3:])
    return folder_names

# npy_path = './LTP-data/'
distilled_folder = "/data/xinqiao/akira/distilled_data/"
npy_path = "/data/xinqiao/akira/distilled_data/"
all_files = glob.glob(npy_path+"*.pkl")

tem_file = all_files[1]
print(tem_file)

UAF_category = ['_operator','_malloc_free','_new_delete_array','_new_delete','_return']
UAF_subcategory = [['_equals'],['_char_','_int_','_int64_','_long_','_struct'],['_char_','_int_','_int64_','_long_','_struct_','_class'],['_char_','_int_','_int64_','_long_','_struct_','_class_','_wchart'],['`_freed_ptr']]
load_folder = "/data/xinqiao/akira/windowed_data_row/"
# filename_num = 587663

path_to_files = "/home/xinqiao/5-trojanai/akira-tcs/workloads/juliet/src/testcases/"
CWE_list = get_CWE_numbers(path_to_files)
# CWE_list = ['121']
CWE_list = ['416']

i = 1; j = 0
filename_cat = UAF_category[i]
filename_subcat = UAF_subcategory[i][j]
keywords = filename_cat + filename_subcat

             
with open(distilled_folder + "CWE_0202_" +keywords+"iisig_interesting_data.pkl", "rb") as f:
    X_interesting = pickle.load(f)
with open(distilled_folder + "CWE_0202_" +keywords+"iisig_common_data.pkl", "rb") as f:
    X_common = pickle.load(f)
with open(distilled_folder + "CWE_0202_" +keywords+"iisig_interesting_labels.pkl", "rb") as f:
    y_interesting = pickle.load(f)   
with open(distilled_folder + "CWE_0202_" +keywords+"iisig_common_labels.pkl", "rb") as f:
    y_common = pickle.load(f) 
                
# with open(distilled_folder + "CWE" +keywords+"iisig_interesting_data.pkl", "wb") as fp:
#     pickle.dump(X_train, fp)
# with open(distilled_folder + "CWE" +keywords+"iisig_common_data.pkl", "wb") as fp:
#     pickle.dump(X_outlier, fp)
# with open(distilled_folder + "CWE" +keywords+"iisig_interesting_labels.pkl", "wb") as fp:
#     pickle.dump(interesting_label, fp)    
# with open(distilled_folder + "CWE" +keywords+"iisig_common_labels.pkl", "wb") as fp:
#     pickle.dump(common_label, fp) 

# tem_data = np.load(tem_file)
X_common_array = np.array(X_common)
X_interesting_array = np.array(X_interesting)
print("X_interesting.shape", X_interesting_array.shape)
print("X_common.shape", X_common_array.shape) # (xxx, 156)

# X_common_array = X_common_array[:1000,:]
# X_interesting_array = X_interesting_array[:100,:]
# (2892, 156)


# %%
# Print the label for different traces (MAIN script)
# version  =2 
# datafolder_path = './processed_LTP_v' + str(version) + '/' 
# processed_files = glob.glob(datafolder_path+"processed_batch1_*.npy")
# # labels 1--> trace A normal, 2--> trace B normal, 3--> insteresting tarces
# # for perplexity_rate in [3,10,15,20,25,30,35]:
perplexity_rate  = 3
if 1: 
    both_data = np.concatenate((X_interesting, X_common), axis=0)
    # all_both_data = np.concatenate(both_data, axis=0)   
    all_both_data = both_data
    # both_labels
    y_interesting_adv = y_interesting + 2 
    both_labels = np.concatenate((y_interesting_adv,y_common), axis=0)
    # all_both_labels = np.concatenate(both_labels, axis=0)
    all_both_labels = both_labels
    print("all_both_data shape is", all_both_data.shape)
    
    X_embedded_all = TSNE(n_components=2, learning_rate='auto',
                    init='random', perplexity=perplexity_rate).fit_transform(all_both_data)
    print("finished TSNE")
    # pdb.set_trace()
    # X_embedded_all = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(all_both_data)

    fig, axis = plt.subplots(1,3, figsize=(24, 6))


    axis[0].scatter(X_embedded_all[:len(y_interesting),0], X_embedded_all[:len(y_interesting),1], marker='o', color='green', s=5)
    axis[0].scatter(X_embedded_all[len(y_interesting):,0], X_embedded_all[len(y_interesting):,1], marker='o', color='blue', s=5)
    # axis[0].scatter(X_embedded_all[all_both_labels==1,0], X_embedded_all[all_both_labels==1,1], marker='o', color='red', s=5)

    axis[1].scatter(X_embedded_all[:len(y_interesting),0], X_embedded_all[:len(y_interesting),1], marker='o', color='green', s=5)
    axis[1].scatter(X_embedded_all[all_both_labels==1,0], X_embedded_all[all_both_labels==1,1], marker='o', color='red', s=5)

    axis[2].scatter(X_embedded_all[len(y_interesting):,0], X_embedded_all[len(y_interesting):,1], marker='o', color='blue', s=5)
    axis[2].scatter(X_embedded_all[all_both_labels==3,0], X_embedded_all[all_both_labels==3,1], marker='o', color='red', s=5)
    
    # axis[3].scatter(X_embedded_all[:len(tem_data_interesting),0], X_embedded_all[:len(tem_data_interesting),1], marker='o', color='red', s=5)

    # axis[1].set_xlim(max_bin_value-one_way_offset, max_bin_value + one_way_offset)
    # axis[0].set_xlim(max_bin_value-one_way_offset, max_bin_value + one_way_offset)
    # normal_per = len(tem_data_processed)/len(X_embedded_all)
    # interesting_per = 1- normal_per
    axis[0].title.set_text("Org UAF data, perplexity_rate" + str(perplexity_rate))
    axis[1].title.set_text("Trace A normal data, {:.2f}".format(len(X_embedded_all[all_both_labels==1,0])/len(X_embedded_all)))
    axis[2].title.set_text("Trace B normal data, {:.2f}".format(len(X_embedded_all[all_both_labels==2,0])/len(X_embedded_all)))
    # axis[3].title.set_text("interesting LTP data, {:.2f}".format(len(X_embedded_all[all_both_labels==3,0])/len(X_embedded_all)))
    save_path = './' + str(len(X_common_array))
    fig.savefig(save_path + '_1208_'+keywords+'_'+str(perplexity_rate)+ '.png')
    # fig.savefig(save_path + 'TSNE0630_2_traces_'+file_name1.split("_")[3] + '_' + file_name2.split("_")[3] + '_perplextity_'+str(perplexity_rate)+ 'batchsize'+file_name2.split("_")[1]+'.png')

# %%
# both_labels.shape
# all_both_data.shape
# both_data.shape
# return 
# import pdb
# pdb.set_trace()
# %%
# Print the label for different traces (all files)
version = 2
datafolder_path = './processed_LTP_v' + str(version) + '/' 
processed_files = glob.glob(datafolder_path+"processed_batch1_50_*.npy")

# labels 1--> trace A normal, 2--> trace B normal, 3--> insteresting tarces
# for perplexity_rate in [3,10,15,20,25,30,35]:
# select_files = processed_files[:2]
# if 1:
for perplexity_rate  in [15,25,35]:
    # for file_number in range(5,20,5):
    for file_number in [100,200,275]:
        select_files = processed_files[:file_number]
        all_data =[]
        all_labels =[]
        # counter = 0
        for processed_file in select_files:
            file_name = os.path.basename(processed_file)
            interesting_filename = 'interesting_' + file_name
            interesting_files_path = datafolder_path + interesting_filename

            tem_data_interesting = np.load(interesting_files_path)
            file_name = os.path.basename(processed_file)
            print("file name is ", file_name)
            tem_data_processed = np.load(processed_file)
            if tem_data_interesting != []:
                all_data.append(np.concatenate((tem_data_interesting, tem_data_processed), axis=0))
            else:
                all_data.append(tem_data_processed)
            print("all_data shape is", len(all_data))
            
            all_labels.append(np.concatenate((np.ones(len(tem_data_interesting))*1, np.ones(len(tem_data_processed))*0),axis=0))
            if len(all_data) >= 15:
                break
        all_all_data = np.concatenate(all_data, axis=0)   
        all_all_labels = np.concatenate(all_labels, axis=0)
        # print("all_both_data shape is", all_both_data.shape)
        
        X_embedded_all = TSNE(n_components=2, learning_rate='auto',
                        init='random', perplexity=perplexity_rate).fit_transform(all_all_data)
        # X_embedded_all = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(all_both_data)

        fig, axis = plt.subplots(1,3, figsize=(16, 6))


        axis[0].scatter(X_embedded_all[all_all_labels==0,0], X_embedded_all[all_all_labels==0,1], marker='o', color='green', s=1)
        # axis[0].scatter(X_embedded_all[all_all_labels==2,0], X_embedded_all[all_all_labels==2,1], marker='o', color='blue', s=5)
        axis[0].scatter(X_embedded_all[all_all_labels==1,0], X_embedded_all[all_all_labels==1,1], marker='o', color='red', s=1)

        axis[1].scatter(X_embedded_all[all_all_labels==0,0], X_embedded_all[all_all_labels==0,1], marker='o', color='green', s=1)
        # axis[2].scatter(X_embedded_all[all_all_labels==2,0], X_embedded_all[all_all_labels==2,1], marker='o', color='blue', s=5)

        axis[2].scatter(X_embedded_all[all_all_labels==1,0], X_embedded_all[all_all_labels==1,1], marker='o', color='red', s=1)

        normal_per = len(X_embedded_all[all_all_labels==0,0])/len(X_embedded_all)
        interesting_per = 1- normal_per
        axis[0].title.set_text("All LTP data, # of traces is: "+ str(len(select_files)))
        axis[1].title.set_text("Common data, {:.2f}".format(len(X_embedded_all[all_all_labels==0,0])/len(X_embedded_all)))
        axis[2].title.set_text("Interesting data, {:.2f}".format(len(X_embedded_all[all_all_labels==1,0])/len(X_embedded_all)))
        # axis[3].title.set_stext("interesting LTP data, {:.2f}".format(len(X_embedded_all[all_all_labels==3,0])/len(X_embedded_all)))
        save_path = 'tsne_akira/'
        fig.savefig(save_path + 'TSNE_v2_new_'+str(len(select_files))+'_traces_perplextity_'+str(perplexity_rate)+ '_batchsize_'+file_name.split("_")[2]+'.png')

# %%
# fig.savefig(save_path + 'TSNE_'+str(len(processed_files))+'_traces_perplextity_'+str(perplexity_rate)+ '_batchsize_'+file_name.split("_")[1]+'.png')
# str(len(processed_files))
tem_data_interesting.shape
# tem_data_interesting = np.load(interesting_files_path)
interesting_files_path

# %%
# ROC AUC for normal windows from two traces and both insteresting windows
tprs = []
aucs = []
import xgboost as xgb
from sklearn.model_selection import cross_val_score, KFold
from sklearn import svm
from sklearn.metrics import mean_squared_error, auc, RocCurveDisplay
cv = KFold(n_splits=3, shuffle=True)

version = 3
datafolder_path = './processed_LTP_v' + str(version) + '/' 
processed_files = glob.glob(datafolder_path+"common_*.npy")

# labels 1--> trace A normal, 2--> trace B normal, 3--> insteresting tarces
# for perplexity_rate in [3,10,15,20,25,30,35]:
# select_files = processed_files[:2]
# if 1:

# for file_number in range(5,20,5):
# for file_number in [2]:
    # file_number = 2
for epoch in range(20):
    random_numbers = np.random.randint(low=0, high=len(processed_files), size=2)
    select_files = [processed_files[i] for i in random_numbers]
    # sublist = [my_list[i] for i in indices]
    all_data =[]
    all_labels =[]
    all_interesting = []
    all_interesting_label = []
    all_normal = []
    all_normal_label = []
    counter = 0
    for processed_file in select_files:
        
        file_name = os.path.basename(processed_file)
        
        interesting_filename = 'interesting_' + file_name[7:]
        interesting_files_path = datafolder_path + interesting_filename

        tem_data_interesting = np.load(interesting_files_path)
        file_name = os.path.basename(processed_file)
        print("file name is ", file_name)
        if counter ==0:
            file_name1 = file_name
        else:
            file_name2 = file_name
        tem_data_processed = np.load(processed_file)
        
        all_normal.append(tem_data_processed)
        all_normal_label.append(np.ones(len(tem_data_processed))*counter)
   
        all_interesting.append(tem_data_interesting)
        all_interesting_label.append(np.ones(len(tem_data_interesting))*counter)
        
        # all_data.append(np.concatenate((tem_data_interesting, tem_data_processed), axis=0))
        # else:
        #     all_data.append(tem_data_processed)
        counter +=1
        # print("all_data shape is", len(all_data))
        # all_labels.append(np.concatenate((np.ones(len(tem_data_interesting))*1, np.ones(len(tem_data_processed))*0),axis=0))
        
    # all_all_data = np.concatenate(all_data, axis=0)   
    # all_all_labels = np.concatenate(all_labels, axis=0)
    all_all_interesting  = np.concatenate(all_interesting, axis=0)
    all_all_interesting_label = np.concatenate(all_interesting_label, axis=0)
    all_all_normal  = np.concatenate(all_normal, axis=0)
    all_all_normal_label = np.concatenate(all_normal_label, axis=0)
    # assert len(all_all_labels) == len(all_all_normal_label) + len(all_all_interesting_label)
    print(len(all_all_normal_label))
    print(len(all_all_interesting_label))
    
    # X = all_all_normal
    # clean_y = np.copy(all_all_normal_label)
    # y = clean_y


    title_all = ['interesting','common','both']


    for exp_num in [0,1]: #0--> AB interesting, 1 --> AB normal, 2 --> AB all 
        if exp_num == 0:
            X = all_all_interesting
            clean_y = np.copy(all_all_interesting_label)
        elif exp_num == 1:
            X = all_all_normal
            clean_y = np.copy(all_all_normal_label)
        elif exp_num ==2:
            X = all_all_data
            clean_y = np.copy(all_all_labels)
        y = clean_y
        xg_reg = xgb.XGBClassifier(objective ='binary:logistic', subsample=0.9,
                        max_depth = 50,n_estimators = 10, use_label_encoder=False)
        # X_embedded_all = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(all_both_data)
        # kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto")
        mean_fpr = np.linspace(0, 1, 100)
        # title = "ROC Xgboost for 2 traces (label 0: trace A "+title_all[exp_num]+" windows Num=" +str(len(clean_y[clean_y==0])) + ") \n (label 1: trace B "+title_all[exp_num]+" windows Num= "+str(len(clean_y[clean_y==1]))+")" 
        title ='ROC Xgboost_'+file_name1.split("_")[7] + '_' +str(len(clean_y[clean_y==0]))+'_'+ file_name2.split("_")[7]+'_'+str(len(clean_y[clean_y==1]))+'_'+str(title_all[exp_num])
        fig, ax = plt.subplots()
        for i, (train, test) in enumerate(cv.split(X,y)):
            xg_reg.fit(X[train], y[train])
            viz = RocCurveDisplay.from_estimator(
                xg_reg,
                X[test],
                y[test],
                name="ROC fold {}".format(i),
                alpha=0.3,
                lw=1,
                ax=ax,
            )
            interp_tpr = np.interp(mean_fpr, viz.fpr, viz.tpr)
            interp_tpr[0] = 0.0
            tprs.append(interp_tpr)
            aucs.append(viz.roc_auc)

        ax.plot([0, 1], [0, 1], linestyle="--", lw=2, color="r", label="Chance", alpha=0.8)

        mean_tpr = np.mean(tprs, axis=0)
        mean_tpr[-1] = 1.0
        mean_auc = auc(mean_fpr, mean_tpr)
        std_auc = np.std(aucs)
        ax.plot(
            mean_fpr,
            mean_tpr,
            color="b",
            label=r"Mean ROC (AUC = %0.3f $\pm$ %0.3f)" % (mean_auc, std_auc),
            lw=2,
            alpha=0.8,
        )

        std_tpr = np.std(tprs, axis=0)
        tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
        tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
        ax.fill_between(
            mean_fpr,
            tprs_lower,
            tprs_upper,
            color="grey",
            alpha=0.2,
            label=r"$\pm$ 1 std. dev.",
        )

        ax.set(
            xlim=[-0.05, 1.05],
            ylim=[-0.05, 1.05],
            title=title,
        )
        ax.legend(loc="lower right")
        # plt.show()
        # fig.savefig(save_path + 'Xgb_ROC_normal_AB_traces_v2.png')
        # if mean_auc > 0.60:
        fig.savefig(save_path + 'Xgb_ROC_'+title_all[exp_num]+'_AB_traces_'+str(epoch)+'_v2_shuffle.png')
        


# %%
# ROC AUC for just insteresting windows

import xgboost as xgb
from sklearn.model_selection import cross_val_score, KFold
from sklearn import svm
from sklearn.metrics import mean_squared_error, auc, RocCurveDisplay
cv = KFold(n_splits=3, shuffle=True)

version = 3
datafolder_path = './processed_LTP_v' + str(version) + '/' 
processed_files = glob.glob(datafolder_path+"interesting_*.npy")

# labels 1--> trace A normal, 2--> trace B normal, 3--> insteresting tarces
# for perplexity_rate in [3,10,15,20,25,30,35]:
# select_files = processed_files[:2]
# if 1:

for epoch in range(20):
    random_numbers = np.random.randint(low=0, high=len(processed_files), size=2)
    select_files = [processed_files[i] for i in random_numbers]
    # sublist = [my_list[i] for i in indices]
    all_data =[]
    all_labels =[]
    all_interesting = []
    all_interesting_label = []
    all_normal = []
    all_normal_label = []
    counter = 0
    for processed_file in select_files:
        
        file_name = os.path.basename(processed_file)
        
        # interesting_filename = 'interesting_' + file_name
        # interesting_files_path = datafolder_path + interesting_filename

        tem_data_interesting = np.load(processed_file)
        # file_name = os.path.basename(processed_file)
        print("file name is ", file_name)
        if counter ==0:
            file_name1 = file_name
        else:
            file_name2 = file_name
        # tem_data_processed = np.load(processed_file)
        
        # all_normal.append(tem_data_processed)
        # all_normal_label.append(np.ones(len(tem_data_processed))*counter)
   
        all_interesting.append(tem_data_interesting[0])
        all_interesting_label.append(np.ones(len(tem_data_interesting[0]))*counter)
        
        # all_data.append(np.concatenate((tem_data_interesting, tem_data_processed), axis=0))
        # else:
        #     all_data.append(tem_data_processed)
        counter +=1
        # print("all_data shape is", len(all_data))
        # all_labels.append(np.concatenate((np.ones(len(tem_data_interesting))*1, np.ones(len(tem_data_processed))*0),axis=0))
        
    # all_all_data = np.concatenate(all_data, axis=0)   
    # all_all_labels = np.concatenate(all_labels, axis=0)
    all_all_interesting  = np.concatenate(all_interesting, axis=0)
    all_all_interesting_label = np.concatenate(all_interesting_label, axis=0)
    # all_all_normal  = np.concatenate(all_normal, axis=0)
    # all_all_normal_label = np.concatenate(all_normal_label, axis=0)
    # assert len(all_all_labels) == len(all_all_normal_label) + len(all_all_interesting_label)
    # print(len(all_all_normal_label))
    print(len(all_all_interesting_label))
    
    # X = all_all_normal
    # clean_y = np.copy(all_all_normal_label)
    # y = clean_y


    title_all = ['interesting','normal','both']


    for exp_num in [0]: #0--> AB interesting, 1 --> AB normal, 2 --> AB all 
        if exp_num == 0:
            X_org = all_all_interesting
            clean_y = np.copy(all_all_interesting_label)
        elif exp_num == 1:
            X_org = all_all_normal
            clean_y = np.copy(all_all_normal_label)
        elif exp_num ==2:
            X_org = all_all_data
            clean_y = np.copy(all_all_labels)
        y_org = clean_y

        tprs = []
        aucs = []       

        from imblearn.over_sampling import SMOTE

        # resample all classes but the majority class
        # smote = SMOTE('minority')
        smote = SMOTE()
        X, y = smote.fit_resample(X_org, y_org)
        xg_reg = xgb.XGBClassifier(objective ='binary:logistic', subsample=0.9,
                        max_depth = 50,n_estimators = 10, use_label_encoder=False)
        # X_embedded_all = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(all_both_data)
        # kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto")
        mean_fpr = np.linspace(0, 1, 100)
        # title = "ROC Xgboost for 2 traces (label 0: trace A "+title_all[exp_num]+" windows Num=" +str(len(clean_y[clean_y==0])) + ") \n (label 1: trace B "+title_all[exp_num]+" windows Num= "+str(len(clean_y[clean_y==1]))+")" 
        title ='ROC Xgboost_'+file_name1.split("_")[4] + '_' +str(len(y[y==0]))+'_'+ file_name2.split("_")[4]+'_'+str(len(y[y==1]))+'_'+str(title_all[exp_num])
        fig, ax = plt.subplots()
        for i, (train, test) in enumerate(cv.split(X,y)):
            xg_reg.fit(X[train], y[train])
            viz = RocCurveDisplay.from_estimator(
                xg_reg,
                X[test],
                y[test],
                name="ROC fold {}".format(i),
                alpha=0.3,
                lw=1,
                ax=ax,
            )
            interp_tpr = np.interp(mean_fpr, viz.fpr, viz.tpr)
            interp_tpr[0] = 0.0
            tprs.append(interp_tpr)
            aucs.append(viz.roc_auc)

        ax.plot([0, 1], [0, 1], linestyle="--", lw=2, color="r", label="Chance", alpha=0.8)

        mean_tpr = np.mean(tprs, axis=0)
        mean_tpr[-1] = 1.0
        mean_auc = auc(mean_fpr, mean_tpr)
        std_auc = np.std(aucs)
        ax.plot(
            mean_fpr,
            mean_tpr,
            color="b",
            label=r"Mean ROC (AUC = %0.3f $\pm$ %0.3f)" % (mean_auc, std_auc),
            lw=2,
            alpha=0.8,
        )

        std_tpr = np.std(tprs, axis=0)
        tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
        tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
        ax.fill_between(
            mean_fpr,
            tprs_lower,
            tprs_upper,
            color="grey",
            alpha=0.2,
            label=r"$\pm$ 1 std. dev.",
        )

        ax.set(
            xlim=[-0.05, 1.05],
            ylim=[-0.05, 1.05],
            title=title,
        )
        ax.legend(loc="lower right")
        # plt.show()
        # fig.savefig(save_path + 'Xgb_ROC_normal_AB_traces_v2.png')
        # if mean_auc > 0.60:
        fig.savefig(save_path + 'Xgb_ROC_'+title_all[exp_num]+'_AB_traces_'+str(epoch)+'_v'+str(version)+'_shuffle.png')
        


# %%
len(all_interesting)
all_interesting[0].shape
tem_data_interesting[0].shape
all_all_interesting_label
# X
len(all_interesting[1])
all_all_interesting.shape
# clean_y.shape

# %%
# str(len(clean_y[clean_y==0]))
X = all_all_interesting
clean_y = np.copy(all_all_interesting_label)
y = clean_y

xg_reg = xgb.XGBClassifier(objective ='binary:logistic', subsample=0.9,
                max_depth = 50,n_estimators = 10, use_label_encoder=False)
# X_embedded_all = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(all_both_data)
# kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto")
mean_fpr = np.linspace(0, 1, 100)
# title = "ROC Xgboos with "+str(len(all_data)) +" traces (label 0: trace A&B normal windows)  and (label 1: trace A&B interesting windows)"
# title = "ROC Xgboost for  "+str(len(all_data)) +" traces (label 0: trace A interesting windows Num=" +str(len(clean_y[clean_y==0])) + ")  and (label 1: interesting windows Num= "+str(len(clean_y[clean_y==1]))+")" 
title = "ROC Xgboost for 2 traces (label 0: trace A interesting windows Num=" +str(len(clean_y[clean_y==0])) + ")  and (label 1: trace B interesting windows Num= "+str(len(clean_y[clean_y==1]))+")" 

fig, ax = plt.subplots()
# all_range = list(range(len(all_both_data)))
for i, (train, test) in enumerate(cv.split(X,y)):
    xg_reg.fit(X[train], y[train])
    viz = RocCurveDisplay.from_estimator(
        xg_reg,
        X[test],
        y[test],
        name="ROC fold {}".format(i),
        alpha=0.3,
        lw=1,
        ax=ax,
    )
    interp_tpr = np.interp(mean_fpr, viz.fpr, viz.tpr)
    interp_tpr[0] = 0.0
    tprs.append(interp_tpr)
    aucs.append(viz.roc_auc)

ax.plot([0, 1], [0, 1], linestyle="--", lw=2, color="r", label="Chance", alpha=0.8)

mean_tpr = np.mean(tprs, axis=0)
mean_tpr[-1] = 1.0
mean_auc = auc(mean_fpr, mean_tpr)
std_auc = np.std(aucs)
ax.plot(
    mean_fpr,
    mean_tpr,
    color="b",
    label=r"Mean ROC (AUC = %0.3f $\pm$ %0.3f)" % (mean_auc, std_auc),
    lw=2,
    alpha=0.8,
)

std_tpr = np.std(tprs, axis=0)
tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
ax.fill_between(
    mean_fpr,
    tprs_lower,
    tprs_upper,
    color="grey",
    alpha=0.2,
    label=r"$\pm$ 1 std. dev.",
)

ax.set(
    xlim=[-0.05, 1.05],
    ylim=[-0.05, 1.05],
    title=title,
)
ax.legend(loc="lower right")
plt.show()

# %%
# ROC AUC for two insteresting windows only 

tprs = []
aucs = []


both_data =[]
both_labels =[]
counter = 0
datafolder_path = './processed_LTP/'
processed_files = glob.glob(datafolder_path+"processed_*.npy")
for processed_file in processed_files[:2]:
    counter+=1
        
    file_name = os.path.basename(processed_file)
    if counter == 1:
        file_name1 = file_name
    else:
        file_name2 = file_name
    interesting_filename = 'interesting_' + file_name
    # org_files = org_folder + file_name[10:]
    interesting_files_path = datafolder_path + interesting_filename
    # file_name = os.path.basename(org_files)
    print("file name is ", interesting_files_path)
    
    tem_data_interesting = np.load(interesting_files_path)
    # X_embedded_interesting = TSNE(n_components=2, learning_rate='auto',
    #               init='random', perplexity=3).fit_transform(tem_data_interesting)
    
    # file_name = os.path.basename(processed_file)
    # print("file name is ", file_name)
    tem_data_processed = np.load(processed_file)
    both_data.append(tem_data_interesting)
    # both_data.append(np.concatenate((tem_data_interesting, tem_data_processed), axis=0))
    print("both_data shape is", len(both_data))
    both_labels.append(np.ones(len(tem_data_interesting))* (counter-1))
    # both_labels.append(np.concatenate((np.ones(len(tem_data_interesting))*3, np.ones(len(tem_data_processed))*counter),axis=0))
    
all_both_data = np.concatenate(both_data, axis=0)   
all_both_labels = np.concatenate(both_labels, axis=0)

cv = KFold(n_splits=3, shuffle=True)
X = all_both_data
# clean_y = 
clean_y = np.copy(all_both_labels)
# clean_y[(clean_y == 1) | (clean_y == 2)] = 0
# clean_y[clean_y == 3] = 1
y = clean_y



xg_reg = xgb.XGBClassifier(objective ='binary:logistic', subsample=0.9,
                max_depth = 50,n_estimators = 10, use_label_encoder=False)
# X_embedded_all = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(all_both_data)
# kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto")
mean_fpr = np.linspace(0, 1, 100)
title = "ROC Xgboos with (label 0: trace A insteresting windows Num=" +str(len(all_both_labels[all_both_labels==0])) + ")  \n (label 1: trace B interesting windows Num= "+str(len(all_both_labels[all_both_labels==1]))+")" 
fig, ax = plt.subplots()
all_range = list(range(len(all_both_data)))
for i, (train, test) in enumerate(cv.split(X,y)):
    xg_reg.fit(X[train], y[train])
    viz = RocCurveDisplay.from_estimator(
        xg_reg,
        X[test],
        y[test],
        name="ROC fold {}".format(i),
        alpha=0.3,
        lw=1,
        ax=ax,
    )
    interp_tpr = np.interp(mean_fpr, viz.fpr, viz.tpr)
    interp_tpr[0] = 0.0
    tprs.append(interp_tpr)
    aucs.append(viz.roc_auc)

ax.plot([0, 1], [0, 1], linestyle="--", lw=2, color="r", label="Chance", alpha=0.8)

mean_tpr = np.mean(tprs, axis=0)
mean_tpr[-1] = 1.0
mean_auc = auc(mean_fpr, mean_tpr)
std_auc = np.std(aucs)
ax.plot(
    mean_fpr,
    mean_tpr,
    color="b",
    label=r"Mean ROC (AUC = %0.3f $\pm$ %0.3f)" % (mean_auc, std_auc),
    lw=2,
    alpha=0.8,
)

std_tpr = np.std(tprs, axis=0)
tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
ax.fill_between(
    mean_fpr,
    tprs_lower,
    tprs_upper,
    color="grey",
    alpha=0.2,
    label=r"$\pm$ 1 std. dev.",
)

ax.set(
    xlim=[-0.05, 1.05],
    ylim=[-0.05, 1.05],
    title=title,
)
ax.legend(loc="lower right")
plt.show()

# %%
# ROC AUC for v3 common and interesting

import xgboost as xgb
from sklearn.model_selection import cross_val_score, KFold
from sklearn import svm
from sklearn.metrics import mean_squared_error, auc, RocCurveDisplay
from imblearn.over_sampling import SMOTE
cv = KFold(n_splits=3, shuffle=True)

version = 3
datafolder_path = './processed_LTP_v' + str(version) + '/' 
processed_files = glob.glob(datafolder_path+"common_*.npy")

# labels 1--> trace A normal, 2--> trace B normal, 3--> insteresting tarces
for epoch in range(20):
    random_numbers = np.random.randint(low=0, high=len(processed_files), size=2)
    select_files = [processed_files[i] for i in random_numbers]
    # sublist = [my_list[i] for i in indices]
    all_data =[]
    all_labels =[]
    all_interesting = []
    all_interesting_label = []
    all_normal = []
    all_normal_label = []
    counter = 0
    for processed_file in select_files:
        file_name = os.path.basename(processed_file)
        interesting_filename = 'interesting_' + file_name[7:]
        print("interesting_filename is ", interesting_filename)
        interesting_files_path = datafolder_path + interesting_filename

        tem_data_interesting = np.load(interesting_files_path)[0]
        file_name = os.path.basename(processed_file)
        print("file name is ", file_name)

        if counter ==0:
            file_name1 = file_name
        else:
            file_name2 = file_name
        tem_data_processed = np.load(processed_file)[0]
        
        all_normal.append(tem_data_processed)
        all_normal_label.append(np.ones(len(tem_data_processed))*counter)
   
        all_interesting.append(tem_data_interesting)
        all_interesting_label.append(np.ones(len(tem_data_interesting))*counter)

        counter +=1
    # all_all_data = np.concatenate(all_data, axis=0)   
    # all_all_labels = np.concatenate(all_labels, axis=0)
    all_all_interesting  = np.concatenate(all_interesting, axis=0)
    all_all_interesting_label = np.concatenate(all_interesting_label, axis=0)
    all_all_normal  = np.concatenate(all_normal, axis=0)
    all_all_normal_label = np.concatenate(all_normal_label, axis=0)
    # assert len(all_all_labels) == len(all_all_normal_label) + len(all_all_interesting_label)
    print(len(all_all_normal_label))
    print(len(all_all_interesting_label))


    title_all = ['interesting','common','both']

    for exp_num in [0,1]: #0--> AB interesting, 1 --> AB normal, 2 --> AB all 
        if exp_num == 0:
            X_org = all_all_interesting
            y_org = np.copy(all_all_interesting_label)
        elif exp_num == 1:
            X_org = all_all_normal
            y_org = np.copy(all_all_normal_label)
        elif exp_num ==2:
            X_org = all_all_data
            y_org = np.copy(all_all_labels)

        tprs = []
        aucs = []
        # resample all classes but the majority class
        smote = SMOTE()
        X, y = smote.fit_resample(X_org, y_org)

        xg_reg = xgb.XGBClassifier(objective ='binary:logistic', subsample=0.9,
                        max_depth = 50,n_estimators = 10, use_label_encoder=False)
        # X_embedded_all = KMeans(n_clusters=2, random_state=0, n_init="auto").fit(all_both_data)
        # kmeans = KMeans(n_clusters=2, random_state=0, n_init="auto")
        mean_fpr = np.linspace(0, 1, 100)
        title ='ROC Xgboost_'+file_name1.split("_")[4] + '_' +str(len(y[y==0]))+'_'+ file_name2.split("_")[4]+'_'+str(len(y[y==1]))+'_'+str(title_all[exp_num])
        fig, ax = plt.subplots()
        for i, (train, test) in enumerate(cv.split(X,y)):
            xg_reg.fit(X[train], y[train])
            viz = RocCurveDisplay.from_estimator(
                xg_reg,
                X[test],
                y[test],
                name="ROC fold {}".format(i),
                alpha=0.3,
                lw=1,
                ax=ax,
            )
            interp_tpr = np.interp(mean_fpr, viz.fpr, viz.tpr)
            interp_tpr[0] = 0.0
            tprs.append(interp_tpr)
            aucs.append(viz.roc_auc)

        ax.plot([0, 1], [0, 1], linestyle="--", lw=2, color="r", label="Chance", alpha=0.8)

        mean_tpr = np.mean(tprs, axis=0)
        mean_tpr[-1] = 1.0
        mean_auc = auc(mean_fpr, mean_tpr)
        std_auc = np.std(aucs)
        ax.plot(
            mean_fpr,
            mean_tpr,
            color="b",
            label=r"Mean ROC (AUC = %0.3f $\pm$ %0.3f)" % (mean_auc, std_auc),
            lw=2,
            alpha=0.8,
        )

        std_tpr = np.std(tprs, axis=0)
        tprs_upper = np.minimum(mean_tpr + std_tpr, 1)
        tprs_lower = np.maximum(mean_tpr - std_tpr, 0)
        ax.fill_between(
            mean_fpr,
            tprs_lower,
            tprs_upper,
            color="grey",
            alpha=0.2,
            label=r"$\pm$ 1 std. dev.",
        )

        ax.set(
            xlim=[-0.05, 1.05],
            ylim=[-0.05, 1.05],
            title=title,
        )
        ax.legend(loc="lower right")
        save_path = 'tsne_akira/v3/'
        if not os.path.isdir(save_path):
            os.mkdir(save_path)
        
        fig.savefig(save_path + 'Xgb_ROC_'+title_all[exp_num]+'_AB_traces_v3_mean_auc_'+str(mean_auc)+'_'+str(epoch)+'_.png')
        



