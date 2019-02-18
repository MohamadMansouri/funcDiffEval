import matplotlib.pyplot as plt
from sklearn import metrics
import numpy as np
import os
from collections import defaultdict

directory_pstv = "./fcatalog_pstv/filtered/"
directory_ngtv = "./fcatalog_ngtv/filtered/"
binaries = [' mirai', ' unrar', ' libclamav', 'all']
color = ['r','g','m','b']
i=0
for filename in os.listdir(directory_pstv):
	y_true = defaultdict(list)
	y_probas = defaultdict(list)
	if filename not in os.listdir(directory_ngtv):
		continue
	i+=1
	
	with open(directory_pstv + filename, 'r') as f:
		for line in f:
			for binary in binaries:
				if line.split(',')[4] == binary or binary == 'all':
					y_probas[binary].append(float(line.split(',')[3])/100)
					y_true[binary].append(1)

	# for binary in binaries:
	# 	if line.split(',')[4] == binary or binary == 'all':
	with open(directory_ngtv + filename, 'r') as f:
		for line in f:
			for binary in binaries:
				if line.split(',')[4] == binary or binary == 'all':
					y_probas[binary].append(float(line.split(',')[3])/100)
					y_true[binary].append(0)

	plt.subplot(230 + i)
	plt.title(filename[:-4])
	k=-1
	for binary in binaries:
		k+=1
		try:
			fpr, tpr, thresholds = metrics.roc_curve(y_true[binary],  y_probas[binary])
			roc_auc = metrics.roc_auc_score(y_true[binary], y_probas[binary])
			if binary == 'all':
				l = 2.0
			else:
				l = 1.0
			plt.plot(fpr, tpr, color[k] ,linewidth=l, label = 'AUC ' + binary + ' = %0.2f' % roc_auc)
			optimal_idx = np.argmax(tpr - fpr)
			optimal_threshold = thresholds[optimal_idx]
			print "threshod=%.2f \t %s %s " %(optimal_threshold*100,filename,binary)
		except:
			pass
	
	plt.legend(loc = 'lower right')
	plt.plot([0, 1], [0, 1],'k--')
	plt.xlim([0, 1])
	plt.ylim([0, 1])
	plt.ylabel('True Positive Rate')
	plt.xlabel('False Positive Rate')
plt.show()