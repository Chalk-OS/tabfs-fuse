#!/bin/bash
#xmake run -w . tabfs \
#    -f -s -o auto_unmount \
#    --imagefile=$1 \
#    ./testmnt
set -x
xmake -r && xmake run -w . tabfs -f -s -o allow_other --dev=test.img ./testmnt
