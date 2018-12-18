#!/usr/bin/python

import os
import subprocess as sp
import sys
import re
import shutil 

thisdir = os.path.dirname(os.path.realpath(__file__))
td = os.path.realpath(thisdir + "/../..")
sys.path.append(td)

from ptest_utils import *

record_debian("guest:/bin/netstat -a", "netstat", "i386")
