CC := gcc
# CFLAGS := -std=c99
CFLAGS:=$(shell pkg-config --cflags r_socket) -g
# Path of the so lib after installation:
# LIB_PATH := /usr/local/lib/libcatalog1.so
LDFLAGS:=$(shell pkg-config --libs r_socket) -lcatalog1 -Lbin 
OUTDIR:=bin

# Build everything:
all: libcatalog1.so eval_fcatalog eval_fcatalog_ngtv eval_fcatalog_objdump
 
 
# # Install the lib libcatalog1.so
# install:
# 	cp ./bin/libcatalog1.so $(LIB_PATH)
 
# Uninstall the lib libcatalog1.so from /usr/lib
# uninstall:
# 	rm -f $(LIB_PATH)
 
clean:
	rm -rf ./bin/eval_fcatalog
	rm -rf ./bin/eval_fcatalog_ngtv
	rm -rf ./bin/eval_fcatalog_objdump

libcatalog1.so: catalog1.c
	$(CC) -shared -Wl,-soname,libcatalog1.so \
                -o $(OUTDIR)/$@ -fPIC $<  -O3


eval_fcatalog: eval_fcatalog.c bin/libcatalog1.so 
	$(CC)  $< -o $(OUTDIR)/$@ $(CFLAGS) $(LDFLAGS)

eval_fcatalog_ngtv: eval_ngtv_fcatalog.c bin/libcatalog1.so 
	$(CC)  $< -o $(OUTDIR)/$@ $(CFLAGS) $(LDFLAGS)

eval_fcatalog_objdump: eval_fcatalog_objdump.c bin/libcatalog1.so 
	$(CC)  $< -o $(OUTDIR)/$@ $(CFLAGS) $(LDFLAGS)

# .PHONY: libcatalog1 clean uninstall install all
