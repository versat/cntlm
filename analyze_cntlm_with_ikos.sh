#!/bin/bash
# Script to analyze Cntlm with IKOS (see https://github.com/NASA-SW-VnV/ikos)
set -e
set -x

make clean
printf 'n\nn\nn\nn\n' | ikos-scan ./configure
printf 'n\n' | ikos-scan make

ikos_options=
# --proc=intra takes too much time (way more than 10 hours on my system)
#ikos_options="${ikos_options} --proc=intra"
ikos_options="${ikos_options} --partitioning=return"
# --domain=gauge-interval-congruence takes too much time (way more than 10 hours on my system)
#ikos_options="${ikos_options} --domain=gauge-interval-congruence"
ikos ${ikos_options} cntlm.bc -o cntlm.db

