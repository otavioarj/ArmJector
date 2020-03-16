#!/bin/bash

if [[ -z "$NDK_DIR" ]]; then
	export NDK_DIR="/home/osboxes/Android/android-ndk-r20b"
	echo "NDK_DIR to $NDK_DIR"
fi

printf ">>AMRV7<<\n";$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi29-clang -Os  -Wall  main.c utils.c  -o armject -s

printf ">>AARCH64<<\n";$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang -Os  -Wall  main.c utils.c  -o armject64 -s
