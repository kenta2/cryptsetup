#!/bin/sh

x86_64-linux-gnu-gcc -o suspend-race-reproducer suspend-race-reproducer.c -g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2 -Wl,-z,relro -Wl,-z,now --pedantic
scp -i ~/.ssh/root@resivo_rsa suspend-race-reproducer root@192.168.122.104:~/
