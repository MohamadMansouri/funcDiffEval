import logging
from idc import *
from idaapi import *
import itertools
import pickle 
import ida_name
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_diskio
import idautils
import ida_name
import os
import zstd
from capstone import *

MIN_FUNC_SIZE = 8
OUT_DIR = "./idenLib/pickles/"

# __EA64__ is set if IDA is running in 64-bit mode
__EA64__ = ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL

if __EA64__ :
    CAPSTONE_MODE = CS_MODE_64
    SIG_EXT = ".sig64"
else:
    CAPSTONE_MODE = CS_MODE_32
    SIG_EXT = ".sig"

def get_ida_logging_handler():
    """
    IDA logger should always be the first one (since it inits the env)
    """
    return logging.getLogger().handlers[0]


logging.basicConfig(level=logging.DEBUG)
get_ida_logging_handler().setLevel(logging.INFO)
g_logger = logging.getLogger("nmt")

# via: http://stackoverflow.com/questions/9816603/range-is-too-large-python
# In Python 2.x, `xrange` can only handle Python 2.x ints,
# which are bound by the native long integer size of the platform.
# `range` allocates a list with all numbers beforehand on Python 2.x,
# and is therefore unsuitable for large arguments.
def zrange(*args):
    start = 0
    end = 0
    if len(args) == 1:
        end = args[0]
    elif len(args) == 2:
        start = args[0]
        end = args[1]
    else:
        raise RuntimeError("Invalid arguments provided to zrange: {:s}".format(str(args)))
    if end < start:
        raise RuntimeError("zrange only iterates from smaller to bigger numbers only: {:d}, {:d}".format(start, end))
    return iter(itertools.count(start).next, end)



def get_functions():
   for i in zrange(get_func_qty()):
        yield getn_func(i)


def getOpcodes(addr, size):
    md = Cs(CS_ARCH_X86, CAPSTONE_MODE)
    md.detail = True
    instr_bytes = ida_bytes.get_bytes(addr, size)
    opcodes_buf = b''
    for i in md.disasm(instr_bytes, size):
        # get last opcode
        if (i.opcode[3] != 0):
            opcodes_buf += "%02x" % (i.opcode[3])
        elif (i.opcode[2] != 0):
            opcodes_buf += "%02x" % (i.opcode[2])
        elif(i.opcode[1] != 0):
            opcodes_buf += "%02x" % (i.opcode[1])
        else:
            opcodes_buf += "%02x" % (i.opcode[0])
    return opcodes_buf

def main():
    idc.auto_wait()
    logger = logging.getLogger("nmt:")
    pickle_list = [] 
    count = 0
    for f in get_functions():
        count += 1
        funcea = f.startEA
        func_size = f.endEA - f.startEA 
        func_name = GetFunctionName(funcea)
        if ( func_size >= MIN_FUNC_SIZE):
            logger.info("[%d / %d] preprocessing %s... "%(count , get_func_qty() ,func_name))
            opcodes = getOpcodes(f.startEA, func_size)
            pickle_list.append((func_name,opcodes,func_size))
        else:
            logger.error("Function %s too short"%(func_name))
    logger.info("Writing pickle file...")
    pickle_out = open(OUT_DIR + get_input_file_path().split('/')[-1] + '.pickle', 'wb')
    pickle.dump(pickle_list, pickle_out)
    pickle_out.close()
    logger.info("Done!")
    ida_pro.qexit(0)


if __name__ == "__main__":
    main()