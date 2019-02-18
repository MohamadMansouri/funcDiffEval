import subprocess, os, fnmatch, codecs, random, shutil, multiprocessing, glob
import sys, bisect, numpy, traceback, re
from math import ceil
from absl import app
from absl import flags
from subprocess import Popen, PIPE, STDOUT
from operator import itemgetter
from collections import defaultdict
import itertools
import pickle
# file_name = NAME-ARCH-COMP-VERS-FLAG.PLAT.txt
NAME = 0
ARCH = 1
COMP = 2
VERS = 3
FLAG = 4
PLAT = 5

RATIO = 2
work_directory = "./pickles/"
out_directory = "./result/"


def FindSymbolFiles():
  return [filename for filename in os.listdir(work_directory) if filename[-7:] == ".pickle"]

def FindModifiedSymbolFiles(modified):
  return [filename for filename in os.listdir(work_directory + modified) if filename[-7:] == ".pickle"]  


def FindDiffX(files, X, dontcare):
  files_pair_list = []

  # file_name = NAME-ARCH-COMP-VERS-FLAG.PLAT
  for file_pair in itertools.combinations(files , r=2):
    fileone = file_pair[0][:-7].split('-') 
    filetwo = file_pair[1][:-7].split('-')
    fileone.append(file_pair[0][:-7].split('.')[-1])
    filetwo.append(file_pair[1][:-7].split('.')[-1])
    append = 1

    for i in range(6):
      if i in dontcare:
        continue

      if i in X:
        if fileone[i] == filetwo[i]:
          append = 0
      else:
        if fileone[i] != filetwo[i]:
          append = 0          

    if append:
      files_pair_list.append(file_pair)

  # random.shuffle(files_pair_list)
  # files_pair_list = files_pair_list[:FLAGS.max_file_pairs]
  return files_pair_list


def WriteInputsX(X, f):
  print X
  f_write = open(out_directory+f+'.txt','w')
  count = 0
  cc=0
  for pair in X:
    file1 = open(work_directory + pair[0])
    file2 = open(work_directory+ pair[1])
    data_file1 = pickle.load(file1)
    data_file2 = pickle.load(file2)
    data_to_write_pstv= {}
    data_to_write_ngtv= {}
    data_to_write_size= {}
    for triplet_1 in data_file1:
      data_to_write_pstv[triplet_1[0]] = triplet_1[1]
      data_to_write_ngtv[triplet_1[0]] = triplet_1[1]
      data_to_write_size[triplet_1[0]] = triplet_1[2]

    for triplet_2 in data_file2:
      if triplet_2[0] in data_to_write_pstv:
        # data_to_write_pstv[triplet_2[0]].append(triplet_2[1])
        string_to_write_pstv = "1 " 
        if triplet_2[1] == data_to_write_pstv[triplet_2[0]]:
          string_to_write_pstv += "1\n"
        else:
          string_to_write_pstv += "0\n"
        f_write.write(string_to_write_pstv)

      k=0
      for name in data_to_write_ngtv:
        size = data_to_write_size[name]
        if name != triplet_2[0] and triplet_2[2]/size < RATIO and size/triplet_2[2] < RATIO:
          string_to_write_ngtv = "0 " 
          if  triplet_2[1] == data_to_write_ngtv[name]:
            string_to_write_ngtv += "1\n"
          else:
            string_to_write_ngtv += "0\n"
          count +=1
          f_write.write(string_to_write_ngtv)

          k+=1
          if(k==3):
            break
    # for name_pstv,name_ngtv in zip(data_to_write_pstv,data_to_write_ngtv):
    #   if len(data_to_write_pstv[name_pstv]) == 2:

    #   if len(data_to_write_ngtv[name_ngtv]) == 2:


    file1.close()
    file2.close()
    cc+=1
    print "[%d / %d] " % (cc,len(X))
  f_write.close()


# print("Creating DB from binaries compiled with different compiler flags...")
# WriteInputsX(FindDiffX(FindSymbolFiles(), list([FLAG]), list([])), "different_flags")

# print("Creating DB from binaries compiled with different versions of compilers...")
# WriteInputsX(FindDiffX(FindSymbolFiles(), list([VERS]), list([])), "different_compiler_versions")

# print("Creating DB from binaries compiled with different compilers...")
# WriteInputsX(FindDiffX(FindSymbolFiles(), list([COMP]), list([VERS])), "different_compilers")

# print("Creating DB from binaries compiled for different architectures...")
# WriteInputsX(FindDiffX(FindSymbolFiles(), list([ARCH]), list([])), "different_archs")

print("Creating DB from binaries compiled for different platforms...")
WriteInputsX(FindDiffX(FindSymbolFiles(), list([PLAT]), list([COMP,VERS,FLAG])), "different_platforms")

# print("Creating DB from random binaries...")
# WriteInputsX(FindDiffX(FindSymbolFiles(), list([]), list([ARCH,COMP,VERS,FLAG,PLAT])), "random")

print("Creating DB of different functions...")
# CreateRepulsionDB()

# print("Creating DB of Modified binaries...")
# CreateModifiedDB()