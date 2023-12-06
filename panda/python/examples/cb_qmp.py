from pandare import Panda
from time import sleep
import json
import tempfile

path = tempfile.mktemp(".sock")
panda = Panda(generic="x86_64", extra_args=["-qmp", f"unix:{path},server,nowait"])

print()
print("QMP example running! To send a QMP command to this VM, run:")
print("""echo '{ "execute": "mycmd", "arguments": { "arg_key" : "arg_val" } }' | socat - UNIX-CONNECT:""" + path + """  | cat""")
print()

@panda.cb_qmp
def on_qmp_command(cmd, arg_json, result_json):
    args = {}
    cmd = panda.ffi.string(cmd).decode() if cmd != panda.ffi.NULL else None
    if cmd != 'mycmd':
        return False
    if arg_json != panda.ffi.NULL:
        args = json.loads(panda.ffi.string(arg_json).decode())

    print(f"PyPANDA handling QMP command {cmd} with args {args}")

    data = {
        "hello": "world",
        "key": "value",
        "0": 1,
    }

    # Dump our result to json and copy it into the result_json buffer
    encoded_data = json.dumps(data).encode()
    result_buffer = panda.ffi.new("char[]", len(encoded_data) + 1) # Null term
    panda.ffi.memmove(result_buffer, encoded_data, len(encoded_data))
    result_json[0] = result_buffer
    return True

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    panda.run_serial_cmd("whoami")
    sleep(300)
    panda.end_analysis()

panda.run()
