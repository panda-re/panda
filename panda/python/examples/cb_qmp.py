from pandare import Panda
from time import sleep

path = "/tmp/qmp.sock"
panda = Panda(generic="x86_64", extra_args=["-qmp", f"unix:{path},server,nowait"])

print("QMP socket path:", path)

# This needs to match the order in qobj_helpers.h which is a copy of a qemu enum
class QType:
    QTYPE_NONE = 0
    QTYPE_QNULL = 1
    QTYPE_QINT = 2
    QTYPE_QSTRING = 3
    QTYPE_QDICT = 4
    QTYPE_QLIST = 5
    QTYPE_QFLOAT = 6
    QTYPE_QBOOL = 7
    QTYPE__MAX = 8

def create_qint(value):
    """
    Creates a QInt QObject for the given integer value.
    """
    qint = panda.ffi.new("QInt *")  # Allocate a new QInt
    qint.base.type = panda.ffi.cast("enum QType", QType.QTYPE_QINT)  # Set the type to QInt
    qint.base.refcnt = 1  # Initialize reference count
    qint.value = value  # Set the integer value
    return qint

def create_qstring(value):
    """
    Creates a QString QObject for the given string value.
    """
    qstring = panda.ffi.new("QString *")  # Adjust this to your QString structure
    qstring.base.type = panda.ffi.cast("enum QType", QType.QTYPE_QSTRING)
    qstring.base.refcnt = 1

    # Set the string value
    qstring.string = panda.ffi.new("char[]", value.encode())
    qstring.length = len(value)
    qstring.capacity = len(value) + 1

    return qstring

def create_qdict(value):
    """
    Recursively creates a QDict QObject for the given dictionary.
    """

    panda.ffi.cdef("QDict *qdict_new(void);")

    return panda.ffi.qdict_new()

    new_qdict = panda.ffi.new("QDict *")
    new_qdict.base.type = panda.ffi.cast("enum QType", QType.QTYPE_QDICT)
    new_qdict.base.refcnt = 1

    new_qdict.size = 512 # XXX what do we set this size to?
    new_qdict.table[0].lh_first = panda.ffi.NULL

    for key, val in value.items():
        add_entry_to_qdict(new_qdict, key, val)
    return new_qdict

def create_qobject(value):
    """
    Creates a QObject for the given value.
    """
    if isinstance(value, int):
        r = create_qint(value)
    elif isinstance(value, str):
        r = create_qstring(value)
    elif isinstance(value, dict):
        r = create_qdict(value)
    else:
        raise TypeError(f"Unsupported type for create_qobject: {type(value)}")

    return panda.ffi.cast("QObject *", r)

def add_entry_to_qdict(qdict, key, value):
    """
    Adds an entry to the given QDict.
    :param qdict: QDict to which the entry will be added
    :param key: Key for the new entry
    :param value: Value for the new entry (can be int, str, or another QDict)
    """
    # Find an empty slot in the table
    index = 0
    while index < 512 and qdict.table[index].lh_first != panda.ffi.NULL:
        index += 1
    if index == 512:
        raise Exception("QDict table is full")

    print("Found open slot for key", key, "at index", index)

    # Create a new QDictEntry
    qdictentry = panda.ffi.new("QDictEntry *")
    qdictentry.key = panda.ffi.new("char[]", key.encode())
    print(f"For key {key} we have value {value}")
    qdictentry.value = panda.ffi.cast("QObject *", create_qobject(value))

    # Now insert the new entry into the table
    qdict.table[index].lh_first = qdictentry
    qdictentry.next.le_next = panda.ffi.NULL
    qdictentry.next.le_prev = panda.ffi.cast("QDictEntry **", qdict.table[index].lh_first)

    #qdict.table[index].lh_first = qdictentry
    #qdictentry.next.le_next = panda.ffi.NULL
    #qdictentry.next.le_prev = panda.ffi.cast("QDictEntry **", qdict.table[index].lh_first)

    # Update the size
    qdict.size += 1

def BROK_add_entry_to_qdict(qdict, key, value):
    """
    Adds an entry to the given QDict, inserting at the tail of the list.
    """
    # Create a new QDictEntry
    qdictentry = panda.ffi.new("QDictEntry *")
    qdictentry.key = panda.ffi.new("char[]", key.encode())
    qdictentry.value = panda.ffi.cast("QObject *", create_qobject(value))

    # Find the tail of the list
    index = 0
    while index < 512:
        if qdict.table[index].lh_first is panda.ffi.NULL:
            break
        else:
            tail = qdict.table[index].lh_first
            while tail.next.le_next is not panda.ffi.NULL:
                tail = tail.next.le_next
            index += 1
    if index == 512:
        raise Exception("QDict table is full")

    # Insert the new entry at the tail of the list
    if qdict.table[index].lh_first is panda.ffi.NULL:
        # This is the first item in the list
        qdict.table[index].lh_first = qdictentry
        qdictentry.next.le_prev = panda.ffi.addressof(qdict.table[index], "lh_first")
    else:
        # Append to the end of the list
        tail.next.le_next = qdictentry
        qdictentry.next.le_prev = panda.ffi.addressof(tail, "next")
    
    # Set the next pointer of the new entry to NULL, as it is now the last element
    qdictentry.next.le_next = panda.ffi.NULL

    # Update the size
    qdict.size += 1



@panda.cb_qmp
def on_qmp_command(cmd_c, arg_dict, ret_dict, error):
    if cmd_c == panda.ffi.NULL or panda.ffi.string(cmd_c) != b"mycmd":
        return False

    #my_result = create_qdict({"mykey": 2, "myreturn": 1})
    #my_result = create_qdict({"mykey": "myval"})
    my_result = create_qdict({})
    
    # Update the ret_dict to point to the new QObject
    ret_dict[0] = panda.ffi.cast("QObject *", my_result)
    return True

@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    panda.run_serial_cmd("whoami")
    sleep(300)
    panda.end_analysis()

panda.run()
