#!/bin/bash
export AFL_NO_UI=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

core=0

for i in {1..5}; do
    run_out="output_run_${i}"
    mkdir -p "${run_out}"

    afl-fuzz \
        -i input \
        -o "${run_out}" \
        -V 86400 \
        -b $core \
        -U -- python3 fuzzer.py @@ > "${run_out}/afl.log" &
    sleep 5
    ((core+=2))
done