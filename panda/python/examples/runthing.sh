#!/bin/bash
for i in `seq 1 100`; do
    python3 speed_comparison.py py >> a.py
done

for i in `seq 1 100`; do
    python3 speed_comparison.py C >> c.py
done
