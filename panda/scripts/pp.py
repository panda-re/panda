#!/usr/bin/env python3
import logging
import os.path
import re
import sys
import textwrap

LOGLEVEL = logging.INFO
logging.basicConfig(format='%(levelname)s: %(message)s', level=LOGLEVEL)

def indent_snippet(label, s):
    if s is None or s == '':
        return '  %s:\n' % (label)
    else:
        return '  %s:\n%s\n' % (label, textwrap.indent(s, '  | '))

def parse_message_block(buf):
    start = buf.find('message')
    if start == -1:
        return (buf.strip(), None, None)

    brace_open = 0
    brace_close = 0
    for i, c in enumerate(buf[start:]):
        if c == '{':
            brace_open += 1
        elif c == '}':
            brace_close += 1
        if brace_open == brace_close and brace_open > 0:
            break

    if brace_open == brace_close and brace_open > 0:
        # ok
        before = buf[:start].strip()
        message = buf[start:start+i+1].strip()
        after = buf[start+i+1:].strip()
    else:
        # unbalanced block
        before = buf[:start].strip()
        message = None
        after = buf[start:].strip()

    logging.debug('message parser\n%s%s%s',
            indent_snippet('before', before),
            indent_snippet('message', message),
            indent_snippet('after', after))

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
        buf += line
    logging.debug('%s\n%s', filename, indent_snippet('content', buf))
    return buf
    
def parse_proto_part(buf):
    messages = []
    rests = []
    while True:
        before, message, after = parse_message_block(buf)
        if before:
            rests.append(before)
        if message is None and after is None:
            # no message found
            break
        elif message is None:
            # unbalanced brace
            logging.error('unbalanced brace\n%s', indent_snippet('block', after))
            break
        else:
            messages.append(message)
            buf = after
    return (messages, rests)

if __name__ == '__main__':
    messages = []
    rests = []
    for plugins_filename in sys.argv[2:]:
        logging.info('processing proto files for plugins in %s', plugins_filename)
        plugins_dir = os.path.dirname(plugins_filename)
        with open(plugins_filename) as plugins_file:
            for plugin_name in plugins_file:
                plugin_name = plugin_name.strip()
                if not len(plugin_name): continue
                if plugin_name[0] == '#': continue
                proto_file = os.path.join(plugins_dir, plugin_name, '%s.proto' % plugin_name)
                if not os.path.isfile(proto_file):
                    logging.debug('no proto file for plugin %s.', plugin_name)
                    continue
                logging.debug('processing %s proto', plugin_name)
                proto_part = get_proto_text(proto_file)
                (m, r) = parse_proto_part(proto_part)
                messages.extend(m)
                rests.extend(r)

    with open(sys.argv[1], "w") as f:
        f.write(textwrap.dedent("""
            syntax = "proto2";
            package panda;
        """).lstrip())
        for message in messages:
            f.write(message + "\n")
        f.write(textwrap.dedent("""
            message LogEntry {
            required uint64 pc = 1;
            required uint64 instr = 2;
        """).lstrip())
        for line in rests:
            f.write(line + "\n")
        f.write ("\n}\n" )

# vim: set tabstop=4 softtabstop=4 expandtab :
