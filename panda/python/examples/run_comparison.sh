#!/bin/bash
# take recording
python3 speed_comparison.py
# record C times
echo "Doing C speeds"
python3 speed_comparison.py C 2>&1 > C_runner
# record python times
echo "Doing Python speeds"
python3 speed_comparison.py Python 2&>1 > Python_runner
# do analysis
echo "Doing analysis"
python3 do_speed_analysis.py