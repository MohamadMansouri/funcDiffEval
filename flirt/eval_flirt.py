import argparse
import sys
import re
import lscan
import os
import base64
import subprocess
import time
from collections import defaultdict
from multiprocessing import Process, Queue, Manager

DBs = {
 "ARCH_DB" : "different_archs.txt",
 "COMP_DB" : "different_compilers.txt",
 "VERS_DB" : "different_compiler_versions.txt",
 "FLAG_DB" : "different_flags.txt",
 # "FUNC_DB" : "different_functions.txt",
 "PLAT_DB" : "different_platforms.txt",
 "RAND_DB" : "random.txt",
 "MOD0_L_DB" : "large_size_modified0.txt",
 "MOD1_L_DB" : "large_size_modified1.txt",
 "MOD2_L_DB" : "large_size_modified2.txt",
 "MOD3_L_DB" : "large_size_modified3.txt",
 "MOD0_M_DB" : "medium_size_modified0.txt",
 "MOD1_M_DB" : "medium_size_modified1.txt",
 "MOD2_M_DB" : "medium_size_modified2.txt",
 "MOD3_M_DB" : "medium_size_modified3.txt",
 "MOD0_S_DB" : "small_size_modified0.txt",
 "MOD1_S_DB" : "small_size_modified1.txt",
 "MOD2_S_DB" : "small_size_modified2.txt",
 "MOD3_S_DB" : "small_size_modified3.txt"
}

DB_PATH = "../db/databases_flirt_sorted"
FILES_PATH = ".."
OUT_PATH = "../results/flirt"

def parse(db_path):
    regex = re.compile( "^(.*):(.*) (.*):(.*) (.*)\n$")
    count = 0

    # for line in f_read:
    #     nb_lines += 1
    # f_read.seek(0,0)

    # skip = (STREAM_READ * (nb_lines) / SAMPLE)-1
    # skip_count = skip
    # read_count = 0
    # total_time = 0
    data = defaultdict(list)
    with open(db_path, 'r') as f_read:
        for line in f_read:
            count += 1
            parsed = regex.match(line)
            data[(parsed.group(1), parsed.group(3))].append((int(parsed.group(2),16), int(parsed.group(4),16), parsed.group(5)))

	print("parsed {} line and created {} entries".format(count, len(data)))
	return data


def get_sig_file(file):
    name = file.split('/')[-1]
    name = FILES_PATH + '/flirt_sig/sig/' + name + '.sig'
    if os.path.isfile(name):
        return name
    else:
        return None


def evaluate(file_pair, addresses, match, format, t):
    file1 = file_pair[0].split('/')[-1]
    file2 = file_pair[1].split('/')[-1]
    bin_addr_exist = [x[0] for x in addresses]
    bin_addr_match = []
    true_pstv = 0
    false_pstv = 0
    for addr_set in addresses:
        bin_addr = addr_set[0]
        sig_addr = addr_set[1]
        func_name = addr_set[2]
        # print bin_addr
        if bin_addr in match.keys():
            if format == 'ELF':
                func_names = [subprocess.check_output([ "c++filt", x ]).decode("utf-8")[:-1] for x in list(match[bin_addr])]
                func_names = [base64.b64encode(x) for x in func_names]
                if func_name in func_names:
                    true_pstv += 1
                    bin_addr_match.append(bin_addr)
                false_pstv += len(func_names)
            if format == 'PE':
                name2addr = []
                for name in list(match[bin_addr]):
                    if name[:4] == 'loc_' or name[:4] == 'sub_':
                        name2addr.append(int(name[4:],16))
                if sig_addr in name2addr:
                    true_pstv += 1 
                    bin_addr_match.append(bin_addr)
                false_pstv += len(name2addr)


    t = time.time() - t
    string_write = "{}, {}, {}, {}, {}, {}, {}, {:.5f}\n".format(true_pstv, false_pstv, len(addresses),
     file1.split('-')[0], file1[file1.index('-')+1:], file2.split('-')[0], file2[file2.index('-')+1:], t)
    return string_write


    # print(addresses)
    # print([ int(x,0) for x in match.keys()])
    # print(match.values())


def main(args):
    if(not args.a):
        db_name = DBs[args.db]
        db_path = DB_PATH + '/' + db_name
        print ( "Evaluating flirt on DB = {} located in {}".format(args.db,db_path))
        data = parse(db_path)
        output = OUT_PATH + '/' + db_name
        write_file = open(output, 'w')
        count = 0
        processed = 0
        for path_pair in data:
            count += 1
            print "[{} / {}] Matching file {} --> {}".format( count, len(data), path_pair[0], path_pair[1])
            sigfile = get_sig_file(path_pair[1])
            if (sigfile != None):
                try:
                    t = time.time()
                    match, format = lscan.lscan_api(sigfile, FILES_PATH + '/' + path_pair[0])
                    if match == format == -1 : 
                        continue
                    string_write = evaluate(path_pair, data[path_pair], match, format,  t )  
                    match.clear()
                    write_file.write(string_write)
                    # t = time.time()
                    # manager = Manager()
                    # l = manager.list()
                    # p = Process(target=lscan.lscan_api, args=(sigfile, FILES_PATH + '/' + path_pair[0],l, ))
                    # p.start()
                    # p.join(timeout=30)
                    # if p.is_alive():
                    #     p.terminate()
                    # if(l):
                    #     match, format = l[0]
                    # # match, format = lscan.lscan_api(sigfile, FILES_PATH + '/' + path_pair[0])
                    #     string_write = evaluate(path_pair, data[path_pair], match, format, t)  
                    #     match.clear()
                    #     write_file.write(string_write)
                    write_file.flush()
                    processed += 1
                    # else:
                        # print "timeout occured"
                except:
                    print "skipping entry because of exception raised"
        write_file.close()
        print "processed {} out of {}".format(processed, len(data))            
    else:
        for db in DBs.keys():
            db_name = DBs[db]
            db_path = DB_PATH + '/' + db_name
            print ( "Evaluating flirt on DB = {} located in {}".format(db,db_path))
            data = parse(db_path)
            output = OUT_PATH + '/' + db_name
            write_file = open(output, 'w')
            count = 0
            processed = 0

            for path_pair in data:
                count += 1
                print "[{} / {}] Matching file {} --> {}".format( count, len(data), path_pair[0], path_pair[1])
                sigfile = get_sig_file(path_pair[1])
                if (sigfile != None):
                    try:
                        t = time.time()
                        match, format = lscan.lscan_api(sigfile, FILES_PATH + '/' + path_pair[0])
                        if match == format == -1 : 
                            continue
                        string_write = evaluate(path_pair, data[path_pair], match, format,  t )  
                        match.clear()
                        write_file.write(string_write)
                        processed += 1
                    except:
                        print "skipping entry because of exception raised"

            write_file.close()
            print "processed {} out of {}".format(processed, len(data))            



if  __name__ == "__main__":
    __parser__ = argparse.ArgumentParser(prog="eval_flirt")
    __parser__.add_argument("-db",
                            choices=DBs.keys(),
                            help="Name of the database")
    __parser__.add_argument("-a",
                            help="Run on all databases",
                            action='store_true')

    # Hello World
    if len(sys.argv) == 1:
        __parser__.print_help()
        exit(1)
    __args__ = __parser__.parse_args()
    main(__args__)