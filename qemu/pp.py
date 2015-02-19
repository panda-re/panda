#!/usr/bin/python

import re
import os.path


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
for plugin in open("panda_plugins/config.panda"):
    p = plugin.strip()
    proto_part_file = "panda_plugins/%s/%s.proto" % (p, p)
    if os.path.isfile(proto_part_file):
        print proto_part_file
        proto_part = get_proto_text(proto_part_file)
        (m, r) = parse_proto_part(proto_part)
        messages.extend(m)
        rests.extend(r)
    

f = open("panda/pandalog.proto", "w")


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
