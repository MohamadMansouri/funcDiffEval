#!/usr/bin/env python3
# Copyright (c) 2017 Conix Cybersecurity
# Copyright (c) 2017 Lancelot Bogard
#
# This file is part of Machoke.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License

import json
import argparse
import os
import sys
import re
import time as TIME
try:
    import r2pipe
    import mmh3
except ImportError as e:
    if "r2pipe" in str(e):
        exit("Error: Unable to load r2pipe module.\n\
        Please install this module using: 'pip install r2pipe'")
    else:
        exit("Error: Unable to load mmh3 module.\n\
        Please install this module using: 'pip install mmh3'")








DBs = {
 "ARCH_DB" : "different_archs.txt",
 "COMP_DB" : "different_compilers.txt",
 "VERS_DB" : "different_compiler_versions.txt",
 "FLAG_DB" : "different_flags.txt",
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

DB_PATH = "../../db/databases_sorted"
FILES_PATH = "../.."
OUT_PATH = "../../results/machoke_ngtv"
STREAM_READ =  10
SAMPLE =  10000

def process_machoke(rdeux, address):
    res = rdeux.cmd('af @ 0x{0}; agj @ 0x{0}'.format(address))
    fgraph = json.loads(res)
    start = TIME.time()
    machoke = get_machoke_from_function(fgraph)
    end = TIME.time()
    mmh3_line = hex(mmh3.hash(machoke) & 0xFFFFFFFF).replace("0x", "").replace("L", "")
    return end - start, fgraph[0]["size"], mmh3_line

def get_machoke_from_function(fgraph):
    """ Return machoke from a function """
    blocks = []
    id_block = 1
    try:
        for block in fgraph[0]["blocks"]:
            blocks.append(
                {'id_block': id_block, 'offset': hex(block["offset"])}
            )
            id_block += 1
    except:
        # print("[ERROR] agj return empty.")
        return ""
    line = ""
    id_block = 1
    for block in fgraph[0]["blocks"]:
        word = "{}:".format(id_block)
        for instruction in block["ops"]:
            # Check if call
            if instruction["type"] == "call":
                word = "{}c,".format(word)
                for ublock in blocks:
                    if hex(instruction["offset"] + 2) == ublock["offset"]:
                        word = "{}{},".format(word, ublock["id_block"])

            # Check if jmp
            if instruction["type"] == "jmp":
                for ublock in blocks:
                    if instruction["esil"] == ublock["offset"]:
                        word = "{}{},".format(word, ublock["id_block"])

            # Check if conditional jmp
            elif instruction["type"] == "cjmp":
                for ublock in blocks:
                    if hex(instruction["jump"]) == ublock["offset"]:
                        word = "{}{},".format(word, ublock["id_block"])
                    if hex(instruction["offset"] + 2) == ublock["offset"]:
                        word = "{}{},".format(word, ublock["id_block"])
            else:
                pass
        if word[-2] == 'c':
            for ublock in blocks:
                if hex(instruction["offset"] + 4) == ublock["offset"]:
                    word = "{}{},".format(word, ublock["id_block"])

            if word[-2] == 'c':
                word = "{}{},".format(word, id_block + 1)

        if word[-1] == ":" and id_block != len(fgraph[0]["blocks"]):
            word = "{}{},".format(word, id_block + 1)
        # Clean word
        if word[-1] == ",":
            word = "{};".format(word[:-1])
        elif word[-1] == ":":
            word = "{};".format(word)
        line = "{}{}".format(line, word)
        id_block += 1
    return line


def evaluate(db_path, DB):
    f_read = open(db_path, 'r')
    output = OUT_PATH + '/' + DBs[DB]
    f_write = open (output, 'w')
    regex = re.compile( "^(.*):(.*) (.*):(.*)\n$")
    old_path1 = ""
    old_path2 = ""
    count = 0
    nb_lines = 0
    read_base = True
    for line in f_read:
        nb_lines += 1
    f_read.seek(0,0)

    skip = (STREAM_READ * (nb_lines) / SAMPLE)-1
    skip_count = skip
    read_count = 0
    total_time = 0
    for line in f_read:
        if skip_count < skip:
            skip_count += 1
            count += 1
            read_base = True
            continue

        start_raw = TIME.time()
        count += 1 
        read_count += 1

        if read_count == STREAM_READ:
            skip_count = 0
            read_count = 0

        parsed = regex.match(line)


        if read_base:
            path1 = FILES_PATH + '/' + parsed.group(1)
            addr1 = parsed.group(2)
            ext1 = path1.split('/')[-1]
        
            if (old_path1 != path1):
                if(count != 1):
                    r21.quit()
                r21 = r2pipe.open(path1)
                old_path1 = path1
            read_base = False
            continue
            
        path2 = FILES_PATH + '/' +parsed.group(3)
        addr2 = parsed.group(4)

        if (old_path2 != path2):
            if(count != 2):
                r22.quit()
            r22 = r2pipe.open(path2)
            old_path2 = path2
        try:
            time1, size1, hash1 = process_machoke(r21, addr1)
            time, size2, hash2 = process_machoke(r22, addr2)
            time += time1
            ext2 = path2.split('/')[-1]
            end_raw = TIME.time()
            time_raw = end_raw - start_raw
            line_to_write = "{}, {}, {}, {}, {}, {}, {}, {}, {:.5f}, {:.5f}\n".format(count, size1, size2, int(hash1 == hash2),
             ext1.split('-')[0], ext1[ext1.index('-')+1:], ext2.split('-')[0], ext2[ext2.index('-')+1:], time, time_raw)
            f_write.write(line_to_write)
            total_time += time_raw
            if(count % 10 == 0):
                print("{} out of {} ({:.2f} %)\t Time elapsed = {:.2f} sec".format(count, nb_lines, 100*float(count)/float(nb_lines), total_time ))
        except:
            print("One Error occured , 1 entry skipped...")
    f_read.close()
    f_write.close()
    r21.quit()
    r22.quit()




def main(args):
    if(not args.a):
        db_name = DBs[args.db]
        db_path = DB_PATH + '/' + db_name
        print ( "Evaluating Machoke on DB = {} located in {}".format(args.db,db_path))
        evaluate(db_path, args.db)
    else:
        for db in DBs.keys():
            db_name = DBs[db]
            db_path = DB_PATH + '/' + db_name
            print ( "Evaluating Machoke on DB = {} located in {}".format(db,db_path))
            evaluate(db_path, db)




if  __name__ == "__main__":
    __parser__ = argparse.ArgumentParser(prog="eval_machoke")
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
