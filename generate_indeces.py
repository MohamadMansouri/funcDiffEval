'''
This python code:
  1. Create symbol files for each binary in the ELF and PE directories. The symbol files contain the address and name of each funtion in the binaries.
  2. Create DB files from each pair of functions found in the symbol files
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

def FindELFFiles():
  """ Returns the list of ELF files. These
  ELF files need to contain objdump-able debug information.
  """
  elf_files = [ filename for filename in glob.iglob(
    FLAGS.executable_directory + 'ELF/**/*', recursive=True)
    if os.path.isfile(filename) ]
  print("Returning list of files from ELF directory: %s" % elf_files)
  return elf_files

def FindPEFiles():
  """ Returns the list of PE files. These
  PE files need to have associated text files (with suffix .debugdump) that
  contains the output of dia2dump in the same directory. """
  exe_files = [ filename for filename in glob.iglob(
    FLAGS.executable_directory + 'PE/**/*.exe',
    recursive=True) if os.path.isfile(filename) ]
  dll_files = [ filename for filename in glob.iglob(
    FLAGS.executable_directory + 'PE/**/*.dll',
    recursive=True) if os.path.isfile(filename) ]
  print(FLAGS.executable_directory + 'PE/**/*.exe')
  result = exe_files + dll_files
  print("Returning list of files from PE directory: %s" % result)
  return result

def FindModifiedFiles():
  """ Returns the list of modified ELF files. These
  ELF files need to contain objdump-able debug information.
  """
  modified_files = [ filename for filename in glob.iglob(
    FLAGS.executable_directory + 'modified/**/*', recursive=True)
    if os.path.isfile(filename) ]
  print("Returning list of files from modified directory: %s" % modified_files)
  return modified_files



def FindSymbolFiles():
  return [filename[:-4] for filename in os.listdir(FLAGS.work_directory) 
  if filename[-4:] == ".txt"]

def FindModifiedSymbolFiles(modified):
  return [filename[:-4] for filename in os.listdir(FLAGS.work_directory + modified) 
  if filename[-4:] == ".txt"]  


def ObtainFunctionSymbols(binary_file, file_format):
  if file_format == "ELF":
    return ObtainELFFunctionSymbols(binary_file)
  elif file_format == "PE":
    return ObtainPEFunctionSymbols(binary_file)
  else:
    return ObtainModifiedFunctionSymbols(binary_file)

def SaneBase64(input_string):
  """ Because Python3 attempts to win 'most idiotic language ever', encoding a
  simple string as base64 without risking to have strange newlines added is
  difficult. This functions is an insane solution: Call command line
  base64encode instead of dealing with Python. """
  encoded_string = subprocess.run(["base64", "-w0"], stdout=PIPE,
    input=bytes(input_string, encoding="utf-8")).stdout.decode("utf-8")
  return encoded_string

def ObtainELFFunctionSymbols(binary_file):
  """ Runs objdump to obtain the symbols in an ELF file and then returns a
  dictionary for this file. """
  result = {}
  symbols = [ line for line in subprocess.check_output(
    [ "objdump", "-t", binary_file ] ).decode("utf-8").split("\n")
      if line.find(" F .text") != -1 ]
  syms_and_address = []
  for sym in symbols:
    tokens = sym.split()
    if tokens[2] == 'F':
      address = int(tokens[0], 16)
      # Run the string through c++filt
      sym = subprocess.check_output([ "c++filt", tokens[5] ]).decode("utf-8")
      if (sym[0] == '_' or sym[0] == '.' ):
        continue
      if(binary_file.startswith("./ELF/Mirai/g++")):
        sym = sym.split('(')[0]
      sym = sym.replace('\n', '')
      # print(address, sym)
      sym = SaneBase64(sym)
      result[address] = sym
  return result

def ObtainModifiedFunctionSymbols(binary_file):
  """ Runs objdump to obtain the symbols in the modified ELF file and then returns a
  dictionary for this file. """
  result = {}
  symbols = [ line for line in subprocess.check_output(
    [ "objdump", "-t", binary_file ] ).decode("utf-8").split("\n")
      if line.find(" F .text") != -1 ]
  syms_and_address = []
  for sym in symbols:
    tokens = sym.split()
    if tokens[2] == 'F':
      address = int(tokens[0], 16)
      # Run the string through c++filt
      sym = subprocess.check_output([ "c++filt", tokens[5] ]).decode("utf-8")
      if (sym[0] == '_' or sym[0] == '.' ):
        continue
      if(binary_file.split('/')[-2] == "g++"):
        sym = sym.split('(')[0]
      sym = sym.replace('\n', '')
      sym = SaneBase64(sym)
      if (sym in ModifiedFunctions(0,0) or sym in ModifiedFunctions(1,0) or sym in ModifiedFunctions(2,0) ):
        result[address] = sym
  return result

def find_nth(haystack, needle, n):
  start = haystack.find(needle)
  while start >= 0 and n > 1:
    start = haystack.find(needle, start+len(needle))
    n -= 1
  return start

def ObtainPEFunctionSymbols(binary_file):
  result = {}
  filetype = subprocess.check_output(["file", "-b", binary_file]).decode("utf-8")
  if filetype == "PE32+ executable (console) x86-64, for MS Windows\n":
    default_base = 0x140000000
  elif filetype == "PE32+ executable (DLL) (console) x86-64, for MS Windows\n" or filetype == "PE32+ executable (DLL) (GUI) x86-64, for MS Windows\n":
    default_base = 0x180000000
  elif filetype == "PE32 executable (console) Intel 80386, for MS Windows\n":
    default_base = 0x400000
  elif filetype == "PE32 executable (DLL) (GUI) Intel 80386, for MS Windows\n":
    default_base = 0x10000000
  elif filetype == "PE32 executable (DLL) (console) Intel 80386, for MS Windows\n":
    default_base = 0x10000000
  else:
    print("Problem: %s has unknown file type" % binary_file)
    print("Filetype is: %s" % filetype)
    sys.exit(1)
  if not os.path.isfile(binary_file + ".debugdump"):
    print("No .debugdump file found, no debug symbols...", end ='')
    return result

  print("working... ", end="")
  try:
    function_lines = [
      line for line in open(binary_file + ".debugdump", "rt", errors='ignore').readlines() if
      line.find("Function") != -1 and line.find("static") != -1
      and line.find("crt") == -1 ]
  except:
    # No debugdump data found
    print("Failed to load debug data.")
    traceback.print_exc(file=sys.stdout)
    return result
  for line in function_lines:
    # The lines we wish to split are of the form:
    # Function : static, [
    symbol = line[ find_nth(line, ", ", 3) + 2 :]
    if line.find("[") == -1:
      continue
    try:
      address = int(line.split("[")[1].split("]")[0], 16) + default_base
    except:
      print("Invalid line, failed to split - %s" % line)
      traceback.print_exc(file=sys.stdout)
      continue
    # We still need to stem and encode the symbol.
    stemmed_symbol = subprocess.run(["./bin/stemsymbol"], stdout=PIPE,
      input=bytes(symbol, encoding="utf-8")).stdout
    if len(stemmed_symbol) > 0:
      result[address] = SaneBase64(stemmed_symbol.decode("utf-8"))
  return result


def ProcessFiles(binaries, file_format):
  for binary_file in binaries:
    # Run objdump


    print("Obtaining function symbols from %s... " % binary_file, end='')
    objdump_symbols = ObtainFunctionSymbols(binary_file, file_format)
    print("got %d symbols..." % len(objdump_symbols), end='')
    
    if len(objdump_symbols) > 0:
      if (file_format == "ELF" ):
        print("Opening and writing symbols_%s.ELF.txt. " % binary_file.split('/')[-1], end='')
        output_file = open( FLAGS.work_directory +
          "symbols_%s.ELF.txt" % binary_file.split('/')[-1], "wt" )
      elif file_format ==  "PE":
        print("Opening and writing symbols_%s.PE.txt. " % (binary_file.split('/')[-1].split('.')[0]))
        output_file = open( FLAGS.work_directory +
          "symbols_%s.PE.txt" % (binary_file.split('/')[-1].split('.')[0]), "wt")
      else:
        if not os.path.exists(FLAGS.work_directory + binary_file.split('/')[-3]):
          os.mkdir(FLAGS.work_directory + binary_file.split('/')[-3])
        print("Opening and writing symbols_%s.ELF.txt. " % binary_file.split('/')[-1], end='')
        output_file = open( FLAGS.work_directory + binary_file.split('/')[-3] +
          "/symbols_%s.ELF.txt" % binary_file.split('/')[-1], "wt" )

      symbols_to_write = []
      for function_address in objdump_symbols:
        symbols_to_write.append((function_address,
          objdump_symbols[function_address]))
      print("Sorting...", end='')
      symbols_to_write.sort(key=lambda a: a[1].lower())
      print("Writing...", end='')
      count = 0
      for address, symbol in symbols_to_write:
        output_string = "%s %16.16lx %s\n" % (binary_file,
          address, symbol)
        output_file.write(output_string)
        count = count + 1
      print("Done (wrote %d symbols)" % count)
      output_file.close()
    else:
      print("No symbols. Skipping.")


def FindDiffX(symbol_files, X, dontcare):
  symbol_files_pair_list = []

  # file_name = NAME-ARCH-COMP-VERS-FLAG.PLAT
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
      files_and_address_list += list(symbol_dict.values())
    random.shuffle(files_and_address_list)
    size = WriteFunctionPair(files_and_address_list, FLAGS.work_directory +
     "databases/%s.txt" % db_name)
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



def CreateRepulsionDB():
  files_and_address_list = []
  try:
    symbol_files = FindSymbolFiles()
    nb = ceil(FLAGS.max_func_pairs / len(symbol_files))
    for i in range(len(symbol_files)):
      idx1 = random.randint(0,len(symbol_files) - 1)
      idx2 = random.randint(0,len(symbol_files) - 1)
      while (idx2 == idx1):
        idx2 = random.randint(0,len(symbol_files))
      symbol_dict1 = defaultdict(list)
      symbol_dict2 = defaultdict(list)
      with open(FLAGS.work_directory + symbol_files[idx1] + ".txt" , "r") as fileone:
        for line in fileone:
          symbol_dict1[line.split()[2]].append((line.split()[0],
             line.split()[1]))
      with open(FLAGS.work_directory + symbol_files[idx2] + ".txt" , "r") as filetwo:
        for line in filetwo:
          symbol_dict2[line.split()[2]].append((line.split()[0],
            line.split()[1]))
      for i in range(nb): 
        func1 = random.choice(list(symbol_dict1.keys()))
        func2 = random.choice(list(symbol_dict2.keys()))
        while (func1 == func2):
          func2 = random.choice(list(symbol_dict2.keys()))
          
        files_and_address_list.append([symbol_dict1[func1][0],symbol_dict2[func2][0]])
    size = WriteFunctionPair(files_and_address_list, FLAGS.work_directory +
       "databases/different_functions.txt")
    print("Done writing %d to the DB \"different_functions.txt\"" % size)
  except:
    print("Error while creating DB \"different_functions.txt\"")  



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

        small_modified += list(symbol_dict_small.values())
        medium_modified += list(symbol_dict_medium.values())
        large_modified += list(symbol_dict_large.values())
        

      random.shuffle(small_modified)
      random.shuffle(medium_modified)
      random.shuffle(large_modified)
      error = -1
      size = WriteFunctionPair(small_modified, FLAGS.work_directory +
       "databases/small_size_modified" + str(i) + ".txt")
      print("Done writing %d to the DB \"small_size_modified" % size + str(i) + ".txt\"" )
      error = -2
      size = WriteFunctionPair(medium_modified, FLAGS.work_directory +
       "databases/medium_size_modified" + str(i) + ".txt")
      print("Done writing %d to the DB \"medium_size_modified" % size + str(i) + ".txt\"" )
      error = -3
      size = WriteFunctionPair(large_modified, FLAGS.work_directory +
       "databases/large_size_modified" + str(i) + ".txt")
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
  for pair in pairs:
    if (len(pair) == 2 and count < FLAGS.max_func_pairs and pair[0][0] != pair[1][0]):
      count +=1
      result.write("%s:%s %s:%s\n" % (pair[0][0], pair[0][1], pair[1][0],
        pair[1][1]))
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

  print("Processing ELF files to extract symbols...")
  ProcessFiles(FindELFFiles(), "ELF")

  print("Processing PE files to extract symbols...")
  ProcessFiles(FindPEFiles(), "PE")

  print("Processing modified versions of files to extract symbols...")
  ProcessFiles(FindModifiedFiles(), "modified")

  # Build Databases for each test...
  print("Grouping extracted symbols for DBs...")
  CreatDB()
if __name__ == '__main__':
  app.run(main)
