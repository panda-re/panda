#!/usr/bin/python

import sys
import re
import os.path
debug = False

pproto_filename = sys.argv[1]

def find_message(buf):
    i = buf.find("message")
    if i == -1:
        return None
    j = buf.find("{", i)
    k = buf.find("}", j)
    before = buf[:i]
    message = buf[i:k+1]
    after = buf[k+1:]
    return (before, message, after)


def get_proto_text(filename):
    buf = ""
    for line in open(filename):
        foo = re.search("^(\s*)\/\/", line)
        if foo:
            continue
        bar = re.search("^(\s*)$", line)
        if bar:
            continue
#        print "line=[%s]" % line   
        buf += line
    return buf
    

def check_blank(buf):
    foo = re.search("^(\s*)$", buf)
    if foo:
        return True
    return buf.strip() 

def parse_proto_part(buf):
    # find the messages
    messages = []
    rests = []
    while True:
        x = find_message(buf)
        if x is None:       
            y = check_blank(buf)
            if not (y is True):
                rests.append(y)
            break
        (before, message, after) = x
        messages.append(message)
#        print "message = [%s]" % message
        y = check_blank(before)
        if not (y is True):
            rests.append(y)
        buf = after
#        print len(after)
    return (messages, rests)





pproto = """
syntax = "proto2";
package panda;
message LogEntry {
required uint64 pc = 1;
required uint64 instr = 2;
"""


messages = []
rests = []

if debug:
    print("PP: {} {}".format(sys.argv[2], sys.argv[3]))

lines = open(sys.argv[2]).readlines() + open(sys.argv[3]).readlines()
plugin_dir = os.path.dirname(sys.argv[2])
for plugin in lines:
    p = plugin.strip()
    if (p[0] == '#'): continue
    proto_part_file = os.path.join(plugin_dir, '%s/%s.proto') % (p, p)
    if os.path.isfile(proto_part_file):
        proto_part = get_proto_text(proto_part_file)
        (m, r) = parse_proto_part(proto_part)
        messages.extend(m)
        rests.extend(r)

if len(sys.argv) > 4:
    if debug:
        print("PP: processing extra plugins at {}".format(sys.argv[4]))
    extra_plugin_config = sys.argv[4]
    extra_plugin_dir = os.path.dirname(extra_plugin_config)
    for plugin in open(extra_plugin_config):
        p = plugin.strip()
        if (p[0] == '#'): continue
        proto_part_file = os.path.join(extra_plugin_dir, '%s/%s.proto') % (p, p)
        if os.path.isfile(proto_part_file):
            proto_part = get_proto_text(proto_part_file)
            (m, r) = parse_proto_part(proto_part)
            messages.extend(m)
            rests.extend(r)

f = open(pproto_filename, "w")

f.write ("""
syntax = "proto2";
package panda;

""")

for message in messages:
    f.write( message + "\n" )

f.write("""

message LogEntry {

required uint64 pc = 1;
required uint64 instr = 2;

""")

for line in rests:
    f.write( line + "\n" )

f.write ("\n}\n" )

f.close()
