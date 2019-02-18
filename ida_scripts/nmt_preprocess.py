import logging
from idc import *
from idaapi import *
import pickle 
import itertools

MIN_FUNC_SIZE = 8
OUT_DIR = "./nmt4binaries/pickles/"


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



class Instructions(object):
	def __init__(self, inst_ea, func_start, func_end):
		super(Instructions, self).__init__()
		self.inst_ea = inst_ea
		self.mnem = GetMnem(inst_ea).upper()	
		self.op = []
		self.func_start = func_start
		self.func_end = func_end
		self.processed = ""

	def build_inst(self):
		self.processed =  self.mnem
		self.process_operand()
		if (len(self.op)):
			self.processed += '~'

		for i, op in enumerate(self.op):
			self.processed += op
			if(i != len(self.op) -1):
				self.processed += ','

	def process_operand(self):
		i = 0
		while True:
			op_type = GetOpType(self.inst_ea, i)
			if  op_type == o_void:
				break
			else:
				op_val = GetOpnd(self.inst_ea, i).upper()
				op_val = "".join(op_val.split())
				op_val = re.sub("#[0-9]*", "0", op_val)			

			if op_type == o_displ:
				self.op.append(Instructions.process_disp(op_val))
			elif op_type == o_mem:
				self.op.append("<STR>")
			elif op_type == o_far or op_type == o_near:
				self.op.append(self.process_jmp(op_val))
			elif op_type == o_imm:
				self.op.append(Instructions.process_imm(op_val))
			else:	
				self.op.append(op_val)
			i+=1
	
	@staticmethod
	def process_imm(val):
		if '-' in val:
			return '-0'
		else:
			return '0'
	
	@staticmethod
	def process_disp(val):
		regex = re.findall("\[.*]", val)
		if len(regex) == 0:
			return ""
		op = regex[0]
		s = op[1:-1]
		op = '['
		for j,o in enumerate(s.split(',')):
			for i,oo  in enumerate(o.split('+')):
				if len(oo.split('-')) > 1:
					oo = oo.split('-')[0] + '-0' 
				if oo[0] <= 'Z' and oo[0] >= 'A':
					op += oo
				else: 
					op+=Instructions.process_imm(oo)
				if(i != len(o.split('+')) -1):
					op+='+'
				if(j != len(s.split(',')) -1) :
					op+=','
		op+=']'
		return op

	def process_jmp(self,val):
		if self.inst_ea >= self.func_start and self.inst_ea <= self.func_end:
			return "FOO"
		else:  
			return "<TAG>"

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
		func_body = '"'
		func_size = f.endEA - f.startEA 
		if ( func_size >= MIN_FUNC_SIZE):
			func_name = GetFunctionName(funcea)
			logger.info("[%d / %d] preprocessing %s... "%(count , get_func_qty() ,func_name))
			inst_ea_list = list(FuncItems(funcea))
			for inst_ea in inst_ea_list:
				OpNum(inst_ea)
				inst = Instructions(inst_ea, f.startEA, f.endEA)
				inst.build_inst()
				func_body += inst.processed 
				if(inst_ea != inst_ea_list[-1]):
					func_body += '\n' 
			func_body += '"'
			pickle_list.append((func_name,func_body,func_size))

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