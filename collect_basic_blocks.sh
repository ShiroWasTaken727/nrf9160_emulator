#!/bin/bash

for i in 1 2 3 4 5; do
    python3 coverage.py output_run_$i
done
