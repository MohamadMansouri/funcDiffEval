import pickle
import glob
import itertools
PICK_DIR= "./pickles/"
OUT_DIR = "./model_inputs/"
RATIO = 2
pickles = glob.glob(PICK_DIR + "*.pickle")


arm = []
x86 = []
x64 = []
for i in pickles:
	if "arm" in i:
		arm.append(i)
	elif "x86" in i:
		x86.append(i)
	elif "x64" in i:
		x64.append(i)
different_arch = []
for file_arm, file_x86 in itertools.product(arm,x86):
	pick_arm = file_arm.split('arm')[-1]
	pick_arm = pick_arm[(pick_arm.index('-') + 1):]
	pick_x86 = file_x86.split('x86')[-1]
	pick_x86 = pick_x86[(pick_x86.index('-') + 1):]
	if pick_arm	== pick_x86:
		different_arch.append((file_x86, file_arm))

different_flag_and_arch = []
for file_arm, file_x86 in itertools.product(arm,x86):
	pick_arm = file_arm.split('arm')[-1]
	pick_arm = pick_arm[(pick_arm.index('-') + 1):]
	pick_x86 = file_x86.split('x86')[-1]
	pick_x86 = pick_x86[(pick_x86.index('-') + 1):]
	if pick_arm.split('-')[-1]	!= pick_x86.split('-')[-1] and pick_arm.split('-')[:-1]	== pick_x86.split('-')[:-1] :
		different_flag_and_arch.append((file_x86, file_arm))

def WriteInputsX(X, f_write):
	f_write.write(",x86_bb,arm_bb,eq\n")
	count = 0
	for pair in X:
		f_pickle_x86 = open(pair[0])
		f_pickle_arm = open(pair[1])
		data_x86 = pickle.load(f_pickle_x86)
		data_arm = pickle.load(f_pickle_arm)
		data_to_write_pstv= {}
		data_to_write_ngtv= {}
		data_to_write_size= {}
		for triplet_x86 in data_x86:
			data_to_write_pstv[triplet_x86[0]] = [triplet_x86[1]]
			data_to_write_ngtv[triplet_x86[0]] = [triplet_x86[1]]
			data_to_write_size[triplet_x86[0]] = triplet_x86[2]

		for triplet_arm in data_arm:
			if triplet_arm[0] in data_to_write_pstv:
				data_to_write_pstv[triplet_arm[0]].append(triplet_arm[1])
			c = 9
			for name in data_to_write_ngtv:
				size = data_to_write_size[name]
				if name != triplet_arm[0] and triplet_arm[2]/size < RATIO and size/triplet_arm[2] < RATIO and len(data_to_write_ngtv[name]) == 1:
					data_to_write_ngtv[name].append(triplet_arm[1])
					if c == 0:
						break
					c-=1
		for name_pstv,name_ngtv in zip(data_to_write_pstv,data_to_write_ngtv):
			if len(data_to_write_pstv[name_pstv]) == 2:
				string_to_write_pstv = "%d,%s,%s,1\n"%(count,data_to_write_pstv[name_pstv][0],data_to_write_pstv[name_pstv][1])
				count +=1
				f_write.write(string_to_write_pstv)
			if len(data_to_write_ngtv[name_ngtv]) == 2:
				string_to_write_ngtv = "%d,%s,%s,0\n"%(count,data_to_write_ngtv[name_ngtv][0],data_to_write_ngtv[name_ngtv][1])
				count +=1
				f_write.write(string_to_write_ngtv)

		f_pickle_x86.close()
		f_pickle_arm.close()
	f_write.close()

# f_write = open(OUT_DIR+"different_archs.txt", "w")
# f_write.write(",x86_bb,arm_bb,eq\n")
# WriteInputsX(different_arch, f_write)





f_write = open(OUT_DIR+"different_flag_and_arch.txt", "w")
WriteInputsX(different_flag_and_arch, f_write)
