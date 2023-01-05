import json
import sys
import argparse

def print_out(sym, fields):
    out = open(f"{sym}.out", 'w')
    delin = ":"

    struct = {}
    if 'type' in fields:
        f = fields['type']
        tmp = f
        ty = ''
        while 'subtype' in tmp:
            ty = tmp['kind'] + "%s "%delin + ty
            tmp = tmp['subtype']

        if 'name' in tmp:
            ty = tmp['name'] + "%s "%delin + ty
        if 'offset' in fields:
            off = fields['offset']
        elif 'address' in fields:
            off = f"{fields['address']:x}"
        ty = ty.strip("%s "%delin)
        struct.update({sym: [ty, off]})
    else:
        for field in fields:
            f = fields[field]['type']
            tmp = f
            ty = ''
            while 'subtype' in tmp:
                ty = tmp['kind'] + "%s "%delin + ty
                tmp = tmp['subtype']

            if 'name' in tmp:
                ty = tmp['name'] + "%s "%delin + ty
            off = fields[field]['offset']
            ty = ty.strip("%s "%delin)
            struct.update({field: [ty, off]})
    struct = {k:v for k, v in sorted(struct.items(), key = lambda item: item[1][1])}

    for field in struct:
        out.write(f"{field=}\n\tty={struct[field][0]} | off={struct[field][1]}\n")
    out.close()
    exit()

parser = argparse.ArgumentParser(
    prog = "J-DCoder",
    description = "Check for symbols or structures in a given (decompressed) symbol table"
)

parser.add_argument('-s', '--sym', default = "task_struct", help="Name of the symbol or structure you wish to see.")
parser.add_argument('-f', '--file', default = "", help = "Path to the symbol table you wish to use. Change the default if you're going to be using it a bunch.")
args = parser.parse_args()

file = args.file
sym = args.sym

f = open(file, 'r')
syms =  json.load(f)
# struct = syms['user_types'][arg_2] to get the struct we want
# fields = struct['fields'] to get all the fields of that struct
# for f in fields:
#     ft = f['type']['name'] for the type of this field
#     off = f['offset'] for the offset we want (decimal I think)

for thing in syms:
    if sym in syms[thing]:
        print(f"Found {sym} in {thing}")
        struct = syms[thing][sym]
        break
#struct = syms['user_types'][sym]
#struct = syms['symbols'][sym]
for k in struct:
    print(f"Super-field: {k}")
    if k == "fields":
        for e in struct[k]:
            print(f"\t{e}")
if 'fields' in struct:
    fields = struct['fields']
else:
    fields = struct

x = input('What field would you like to see? (Type "end" to stop or "all" to see all fields)\n')

if x == "all":
    print_out(sym, fields)

while x != "end":
    print('')
    if x in fields:
        print(fields[x])
        f = fields[x]['type']
        tmp = f
        ty = ''
        while 'subtype' in tmp:
            ty = tmp['kind'] + ' ' + ty
            tmp = tmp['subtype']

        if 'name' in tmp:
            ty = tmp['name'] + ' ' + ty
        off = fields[x]['offset']
        ty = ty.strip()
        print(f"{ty=} | {off=}")
    else:
        print(f"{x=} not in fields")
    x = input("\nWhat now? (Type \"end\" to stop)\n")
