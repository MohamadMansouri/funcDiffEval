'''
This python code was written to create another version of the database that contains names of the functions
See generate_indeces.py
'''

#!/usr/bin/python3

import subprocess, os, fnmatch, codecs, random, shutil, multiprocessing, glob
import sys, bisect, numpy, traceback, re
from math import ceil
from absl import app
from absl import flags
from subprocess import Popen, PIPE, STDOUT
from operator import itemgetter
from collections import defaultdict
import itertools
flags.DEFINE_string('work_directory',
  "./db/",
  "The directory into whre the database will be created")

# Clobber existing data directory or not.
flags.DEFINE_boolean('clobber', False, "Clobber output directory or not.")

# Directory for executable files to train on.
flags.DEFINE_string('executable_directory', './',
  "The directory where the ELF and PE executables to train on can be found " +\
  "in their relevant subdirectories ELF/**/* and PE/**/*")

# Max number of pairs for the created dataset.
flags.DEFINE_integer('max_func_pairs', 1000000, "Max number of function pairs for " +
  "the created databases")
flags.DEFINE_integer('max_file_pairs', 5000, "Max number of file pairs for " +
  "the created databases")
#=============================================================================

FLAGS = flags.FLAGS

# file_name = NAME-ARCH-COMP-VERS-FLAG.PLAT.txt
NAME = 0
ARCH = 1
COMP = 2
VERS = 3
FLAG = 4
PLAT = 5




def FindSymbolFiles():
  return [filename[:-4] for filename in os.listdir(FLAGS.work_directory) 
  if filename[-4:] == ".txt"]

def FindModifiedSymbolFiles(modified):
  return [filename[:-4] for filename in os.listdir(FLAGS.work_directory + modified) 
  if filename[-4:] == ".txt"]  



def FindDiffX(symbol_files, X, dontcare):
  symbol_files_pair_list = []

  # file_name = NAME-ARCH-COMP-VERS-FLAG.PLAT.txt
  for file_pair in itertools.combinations(symbol_files , r=2):
    fileone = file_pair[0].split('-') 
    filetwo = file_pair[1].split('-')
    fileone.append(file_pair[0].split('.')[-1])
    filetwo.append(file_pair[1].split('.')[-1])
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
      symbol_files_pair_list.append(file_pair)

  random.shuffle(symbol_files_pair_list)
  symbol_files_pair_list = symbol_files_pair_list[:FLAGS.max_file_pairs]
  return symbol_files_pair_list


def FindandWriteFunctionPair(symbol_files_pair_list, db_name):
  files_and_address_list = []
  try:
    for symbol_file_pair in symbol_files_pair_list:
      symbol_dict = defaultdict(list)
      with open(FLAGS.work_directory + symbol_file_pair[0] + ".txt" , "r") as fileone:
        for line in fileone:
          symbol_dict[line.split()[2]].append((line.split()[0], line.split()[1]))
      with open(FLAGS.work_directory + symbol_file_pair[1] + ".txt" , "r") as filetwo:
        for line in filetwo:
          if line.split()[2] in symbol_dict:
            symbol_dict[line.split()[2]].append((line.split()[0], line.split()[1]))
      files_and_address_list += list(symbol_dict.items())
    random.shuffle(files_and_address_list)
    size = WriteFunctionPair(files_and_address_list, FLAGS.work_directory +
     "databases_flirt/%s.txt" % db_name)
    print("Done writing %d to the DB \"%s.txt\"" % (size, db_name) )
  except:
      print("Error while creating DB \"%s.txt\"" % db_name)  

def CreatDB():
  if not os.path.exists(FLAGS.work_directory + "/databases"):
    os.mkdir(FLAGS.work_directory + "databases")
  
  print("Creating DB from binaries compiled with different compiler flags..." , end=" ")
  FindandWriteFunctionPair(FindDiffX(FindSymbolFiles(), list([FLAG]), list([])), "different_flags")
  
  print("Creating DB from binaries compiled with different versions of compilers...", end = " ")
  FindandWriteFunctionPair(FindDiffX(FindSymbolFiles(), list([VERS]), list([])), "different_compiler_versions")
  
  print("Creating DB from binaries compiled with different compilers...", end = " ")
  FindandWriteFunctionPair(FindDiffX(FindSymbolFiles(), list([COMP]), list([VERS])), "different_compilers")

  print("Creating DB from binaries compiled for different architectures...", end = " ")
  FindandWriteFunctionPair(FindDiffX(FindSymbolFiles(), list([ARCH]), list([])), "different_archs")
  
  print("Creating DB from binaries compiled for different platforms...", end = " ")
  FindandWriteFunctionPair(FindDiffX(FindSymbolFiles(), list([PLAT]), list([COMP,VERS,FLAG])), "different_platforms")
  
  print("Creating DB from random binaries...", end = " ")
  FindandWriteFunctionPair(FindDiffX(FindSymbolFiles(), list([]), list([ARCH,COMP,VERS,FLAG,PLAT])), "random")

  print("Creating DB of Modified binaries...")
  CreateModifiedDB()






def CreateModifiedDB():
  try:
    error = 0
    for i in range(0,4):
      small_modified = []
      medium_modified = []
      large_modified = []
      for symbol_file in FindModifiedSymbolFiles("modified" + str(i)):
        symbol_dict_small = defaultdict(list)
        symbol_dict_medium = defaultdict(list)
        symbol_dict_large = defaultdict(list)
        with open(FLAGS.work_directory + "modified" + str(i) + "/" + symbol_file + ".txt" , "r") as fileone:
          for line in fileone:
            if line.split()[2] in ModifiedFunctions(0,i): 
              symbol_dict_small[line.split()[2]].append((line.split()[0],
                line.split()[1]))
            elif line.split()[2] in ModifiedFunctions(1,i): 
              symbol_dict_medium[line.split()[2]].append((line.split()[0],
                line.split()[1]))
            elif line.split()[2] in ModifiedFunctions(2,i): 
              symbol_dict_large[line.split()[2]].append((line.split()[0],
                line.split()[1]))
        with open(FLAGS.work_directory + symbol_file + ".txt" , "r") as filetwo:
          for line in filetwo:
            if line.split()[2] in symbol_dict_small:
              symbol_dict_small[line.split()[2]].append((line.split()[0],
               line.split()[1]))
            elif line.split()[2] in symbol_dict_medium:
              symbol_dict_medium[line.split()[2]].append((line.split()[0],
               line.split()[1]))
            elif line.split()[2] in symbol_dict_large:
              symbol_dict_large[line.split()[2]].append((line.split()[0],
               line.split()[1]))

        small_modified += list(symbol_dict_small.items())
        medium_modified += list(symbol_dict_medium.items())
        large_modified += list(symbol_dict_large.items())
        

      random.shuffle(small_modified)
      random.shuffle(medium_modified)
      random.shuffle(large_modified)
      error = -1
      size = WriteFunctionPair(small_modified, FLAGS.work_directory +
       "databases_flirt/small_size_modified" + str(i) + ".txt")
      print("Done writing %d to the DB \"small_size_modified" % size + str(i) + ".txt\"" )
      error = -2
      size = WriteFunctionPair(medium_modified, FLAGS.work_directory +
       "databases_flirt/medium_size_modified" + str(i) + ".txt")
      print("Done writing %d to the DB \"medium_size_modified" % size + str(i) + ".txt\"" )
      error = -3
      size = WriteFunctionPair(large_modified, FLAGS.work_directory +
       "databases_flirt/large_size_modified" + str(i) + ".txt")
      print("Done writing %d to the DB \"large_size_modified" % size + str(i) + ".txt\"")
  except IOError:
    if error == -1:
      print("Error while creating \"small_size_modified" + str(i) + ".txt\" database")
    elif error == -2:
      print("Error while creating \"medium_size_modified" + str(i) + ".txt\" database")
    elif error == -3:
      print("Error while creating \"large_size_modified" + str(i) + ".txt\" database")
    else:
      print("Error while creating modified databases (error = %d , sf = %s)" % (error, symbol_file))



def WriteFunctionPair( pairs, output ):
  """
  Take a set of pairs ((file_locA, addressA), (file_locB, addressB)) and write them
  into a file as:
    file_locA:addressA file_locB:addressB
  """
  result = open(output,"wt")
  count = 0
  for entry in pairs:
    pair = entry[1]
    if (len(pair) == 2 and count < FLAGS.max_func_pairs and pair[0][0] != pair[1][0]):
      count +=1
      result.write("%s:%s %s:%s %s\n" % (pair[0][0], pair[0][1], pair[1][0],
        pair[1][1], entry[0]))
  result.close()
  return count

# Modification types:
# -------------------
# 0 : change a const 
# 1 : add a check
# 2 : remove one line
# 3 : negate if condition


# Small functions
# ---------------
# attack_get_opt_str
# rand_next 3
# add_attack 3
# resolv_domain_to_hostname
# checksum_generic

# Medium Functions
# ---------------
# attack_parse
# ensure_single_instance
# resolv_lookup
# attack_start
# util_atoi

# Large Functions
# --------------
# attack_tcp_stomp
# killer_init
# main
# attack_app_http
# attack_udp_dns

def ModifiedFunctions(size, modified):
  if size == 0:
    if modified == 3:
      return ["YXR0YWNrX2dldF9vcHRfc3Ry", "cmVzb2x2X2RvbWFpbl90b19ob3N0bmFtZQ==", "Y2hlY2tzdW1fZ2VuZXJpYw==" ]
    else:
      return ["YXR0YWNrX2dldF9vcHRfc3Ry","cmFuZF9uZXh0", "YWRkX2F0dGFjaw==", "cmVzb2x2X2RvbWFpbl90b19ob3N0bmFtZQ==", "Y2hlY2tzdW1fZ2VuZXJpYw==" ]
  elif size == 1:
    return ["YXR0YWNrX3BhcnNl" , "ZW5zdXJlX3NpbmdsZV9pbnN0YW5jZQ==", "cmVzb2x2X2xvb2t1cA==", "YXR0YWNrX3N0YXJ0" ,"dXRpbF9hdG9p"]
  elif size == 2:
    return ["YXR0YWNrX3RjcF9zdG9tcA==", "a2lsbGVyX2luaXQ=", "bWFpbg==", "YXR0YWNrX2FwcF9odHRw", "YXR0YWNrX3VkcF9kbnM="]
  else :
    return []
 
def main(argv):
  del argv # unused.

  # Refuse to run on Python less than 3.5 (unpredictable!).

  if sys.version_info[0] < 3 or sys.version_info[1] < 5:
    print("This script requires Python version 3.5 or higher.")
    sys.exit(1)

  if FLAGS.clobber:
    shutil.rmtree(FLAGS.work_directory)
    os.mkdir(FLAGS.work_directory)

  if FLAGS.work_directory[-1] != '/':
    FLAGS.work_directory = FLAGS.work_directory + '/'

  # Build Databases for each test...
  print("Grouping extracted symbols for DBs...")
  CreatDB()
if __name__ == '__main__':
  app.run(main)
