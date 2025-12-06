#!/usr/bin/env python3

import sys
import json

# dwarfdump -dil $PROG

def parse_die(ent):
    """
    Parses a single DWARF Debugging Information Entry (DIE) line from dwarfdump output.

    The line is expected to start after the DIE tag (e.g., '<1><0x45> DW_TAG_... >').
    It extracts DWARF attributes (DW_AT_*) and their values.

    Args:
        ent (str): A string containing the DWARF attributes and values for a DIE.

    Returns:
        dict: A dictionary where keys are DWARF attribute names (str) and
              values are the attribute data (str).
    """
    result = {}
    for e in ent.split('> ')[1:]:
        while e.endswith('>'):
            e = e[:-1]
        if not e.startswith('DW_AT_'):
            continue
        dat = e.split('<')
        attr = dat[0].strip()
        for v in dat[1:]:
            v = v.strip()
            if v:
                result[attr] = v
    return result

def parse_section(input_data: str) -> dict:
    """
    Parses the raw dwarfdump output into sections, separating .debug_info
    and .debug_line entries.

    Args:
        input_data (str): The raw content of the dwarfdump output.

    Returns:
        dict: A dictionary with keys '.debug_line' and '.debug_info'.
              Each value is a list of relevant string lines from that section.
              A 'None' marker is added to .debug_line to signal the end of a CU's
              line table.
    """
    result = {'.debug_line': [], '.debug_info': []}
    data = input_data.strip().split('\n')
    for l in data:
        l = l.strip()
        if l.startswith("0x"):
            result['.debug_line'].append(l)
            # Signal End of Text
            if 'ET' in l.split():
                result['.debug_line'].append(None)
        elif l.startswith("<") and not l.startswith("<pc>"):
            result['.debug_info'].append(l)
    return result

def reprocess_ops(ops):
    """
    Converts DWARF location/frame base operation values from strings to integers,
    handling hexadecimal addresses.

    Args:
        ops (list): A list of strings representing DWARF operations and operands.

    Returns:
        list: A list with operands converted to integer types where applicable.
    """
    out = []
    for op in ops:
        if op.startswith('DW_'):
            out.append(op)
        elif type(op) == str:
            if op.lstrip('-+').startswith("0x"):
                out.append(int(op, 16))
            else:
                out.append(int(op))
        else:
            out.append(op)
    return out


class TypeDB(object):
    """
    A database to store and manage DWARF type information (TypeInfo objects)
    indexed by Compilation Unit (CU) offset and type offset within the CU.
    """
    def __init__(self):
        """Initializes an empty dictionary to store type data."""
        self.data = {}

    def insert(self, cu, off, ty):
        """
        Inserts a TypeInfo object into the database.

        Args:
            cu (int): The offset of the Compilation Unit (CU).
            off (int): The offset of the type within the CU.
            ty (TypeInfo): The TypeInfo object to store.
        """
        if cu not in self.data:
            self.data[cu] = {}
        if off not in self.data[cu]:
            self.data[cu][off] = ty

    def jsondump(self):
        """
        Prepares the database content for JSON serialization.

        Returns:
            dict: A nested dictionary structure ready for JSON output.
        """
        jout = {}
        for cu in self.data:
            jout[cu] = {}
            for off in self.data[cu]:
                jout[cu][off] = self.data[cu][off].jsondump()
        return jout

class LineDB(object):
    """
    A database to store and manage source code line number and address mapping (LineRange objects).
    """
    def __init__(self):
        """Initializes an empty dictionary to store line data."""
        self.data = {}

    def _find_best_fit(self, srcfn, lno, addr):
        """
        (Internal) Finds the best-fitting LineRange entry for a previous line number
        that should be extended to cover the current address range.

        Args:
            srcfn (str): Source file name.
            lno (int): Line number to search for.
            addr (int): Current address.

        Returns:
            int: The index of the best-fit LineRange, or -1 if none is found.
        """
        r = [-1, -1]
        for i in range(len(self.data[srcfn])):
            if self.data[srcfn][i].lno == lno:
                if r[1] < self.data[srcfn][i].highpc and addr > self.data[srcfn][i].highpc:
                    r = [i, self.data[srcfn][i].highpc]
        return r[0]

    def insert(self, srcfn, lno, col, addr, func=None):
        """
        Inserts or updates a code address to line number mapping.

        Args:
            srcfn (str): Source file name.
            lno (int): Line number.
            col (int): Column number.
            addr (int): Start address of the line range.
            func (int, optional): Address of the enclosing function. Defaults to None.
        """
        if srcfn not in self.data:
            self.data[srcfn] = []

        if self.data[srcfn] and lno < self.data[srcfn][-1].lno:
            i = -1
        else:
            i = self._find_best_fit(srcfn, lno, addr)
        if i == -1:
            self.data[srcfn].append(LineRange(lno, col, addr, addr, func))
            self.data[srcfn].sort(key = lambda x: x.lno)

        prevlno = lno-1
        i = self._find_best_fit(srcfn, prevlno, addr)
        while prevlno > 0 and i == -1:
            prevlno -= 1
            i = self._find_best_fit(srcfn, prevlno, addr)
        if i != -1:
            self.data[srcfn][i].highpc = addr

    def update_function(self, base_addr, end_addr, finfo):
        """
        Updates the function association for a range of line entries.

        Args:
            base_addr (int): Start address of the function.
            end_addr (int): End address of the function.
            finfo (FuncInfo): The function information object.

        Returns:
            tuple or None: (source_filename, line_number) of the function declaration,
                           or None if not found.
        """
        srcinfo = None
        for srcfn in self.data:
            for i in range(len(self.data[srcfn])):
                if self.data[srcfn][i].lowpc == base_addr:
                    srcinfo = (srcfn, self.data[srcfn][i].lno)
                if self.data[srcfn][i].lowpc >= base_addr \
                        and self.data[srcfn][i].highpc < end_addr:
                    self.data[srcfn][i].func = finfo.scope.lowpc
        return srcinfo

    def jsondump(self):
        """
        Prepares the database content for JSON serialization.

        Returns:
            dict: A dictionary mapping source file names to lists of line range data.
        """
        jout = {}
        for srcfn in self.data:
            key = srcfn
            while srcfn[0] in ['"', "'"]:
                srcfn = srcfn[1:]
            while srcfn[-1] in ['"', "'"]:
                srcfn = srcfn[:-1]
            jout[srcfn] = []
            for lr in self.data[key]:
                jout[srcfn].append(lr.jsondump())
        return jout

class GlobVarDB(object):
    """
    A database to store and manage global variable information (VarInfo objects)
    indexed by Compilation Unit (CU) offset.
    """
    def __init__(self):
        """Initializes an empty dictionary to store global variable data."""
        self.data = {}

    def insert(self, cu, var):
        """
        Inserts a global variable into the database.

        Args:
            cu (int): The offset of the Compilation Unit (CU).
            var (VarInfo): The VarInfo object to store.
        """
        if cu not in self.data:
            self.data[cu] = set()
        self.data[cu].add(var)

    def jsondump(self):
        """
        Prepares the database content for JSON serialization.

        Returns:
            dict: A dictionary mapping CU offsets to lists of global variable data.
        """
        jout = {}
        for cu in self.data:
            jout[cu] = [f.jsondump() for f in self.data[cu]]
        return jout

class FunctionDB(object):
    """
    A database to store and manage function information (FuncInfo objects)
    indexed by Compilation Unit (CU) offset.
    """
    def __init__(self):
        """Initializes an empty dictionary to store function data."""
        self.data = {}

    def insert(self, cu, f):
        """
        Inserts a function into the database.

        Args:
            cu (int): The offset of the Compilation Unit (CU).
            f (FuncInfo): The FuncInfo object to store.
        """
        if cu not in self.data:
            self.data[cu] = set()
        self.data[cu].add(f)

    def jsondump(self):
        """
        Prepares the database content for JSON serialization.

        Returns:
            dict: A dictionary mapping CU offsets to lists of function data.
        """
        jout = {}
        for cu in self.data:
            jout[cu] = [f.jsondump() for f in self.data[cu]]
        return jout


class VarInfo(object):
    """Stores DWARF information for a variable (local, global, or parameter)."""
    def __init__(self, name, cu_off):
        """
        Initializes VarInfo.

        Args:
            name (str): Variable name.
            cu_off (int): Compilation Unit offset.
        """
        self.name = name
        self.cu_offset = cu_off
        self.scope = None
        self.decl_lno = None
        self.decl_fn = None
        self.loc_op = []
        self.type = None

    def jsondump(self):
        """
        Prepares the variable info for JSON serialization.

        Returns:
            dict: A dictionary containing all variable attributes.
        """
        return {'name': self.name,
                'cu_offset': self.cu_offset,
                'scope': self.scope.jsondump(),
                'decl_lno': self.decl_lno,
                'decl_fn': self.decl_fn,
                'loc_op': self.loc_op,
                'type': self.type}

class FuncInfo(object):
    """Stores DWARF information for a function (subprogram)."""
    def __init__(self, cu_off, name, scope, fb_op):
        """
        Initializes FuncInfo.

        Args:
            cu_off (int): Compilation Unit offset.
            name (str): Function name.
            scope (Scope): The memory range (low/high PC) of the function.
            fb_op (list): DWARF operation list for the frame base.
        """
        self.cu_offset = cu_off
        self.name = name
        self.scope = scope
        self.framebase = fb_op
        self.fn = None
        self.lno = None
        self.varlist = []

    def jsondump(self):
        """
        Prepares the function info for JSON serialization.

        Returns:
            dict: A dictionary containing all function attributes.
        """
        return {'name': self.name,
                'cu_offset': self.cu_offset,
                'scope': self.scope.jsondump(),
                'framebase': self.framebase,
                'fn': self.fn,
                'lno': self.lno,
                'varlist': [v.jsondump() for v in self.varlist]}

class TypeInfo(object):
    """Base class for all DWARF type information."""
    def __init__(self, name):
        """
        Initializes TypeInfo.

        Args:
            name (str): Type name.
        """
        self.name = name

    def jsondump(self):
        """
        Prepares the base type info for JSON serialization.

        Returns:
            dict: A dictionary containing the type name.
        """
        return {'name': self.name}

class StructType(TypeInfo):
    """Stores DWARF information for a structure or class."""
    def __init__(self, name, cu_off, size):
        """
        Initializes StructType.

        Args:
            name (str): Struct name.
            cu_off (int): Compilation Unit offset.
            size (int): Size of the struct in bytes.
        """
        TypeInfo.__init__(self, name)
        self.size = size
        self.cu_off = cu_off
        self.children = {}  # <member_offset: (name, type_offset)>

    def jsondump(self):
        """
        Prepares the struct info for JSON serialization.

        Returns:
            dict: A dictionary containing struct-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'StructType',
                'size': self.size,
                'cu_off': self.cu_off,
                'children': self.children,
                })
        return d

class BaseType(TypeInfo):
    """Stores DWARF information for a fundamental type (e.g., int, float)."""
    def __init__(self, name, size):
        """
        Initializes BaseType.

        Args:
            name (str): Base type name.
            size (int): Size of the base type in bytes.
        """
        TypeInfo.__init__(self, name)
        self.size = size

    def jsondump(self):
        """
        Prepares the base type info for JSON serialization.

        Returns:
            dict: A dictionary containing base type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'BaseType',
                'size': self.size,
                })
        return d

class SugarType(TypeInfo):
    """Base class for types that are aliases or modifiers (e.g., typedef, const)."""
    def __init__(self, name, cu_off):
        """
        Initializes SugarType.

        Args:
            name (str): Type name/alias.
            cu_off (int): Compilation Unit offset.
        """
        TypeInfo.__init__(self, name)
        self.cu_off = cu_off
        self.ref = None

    def jsondump(self):
        """
        Prepares the sugar type info for JSON serialization.

        Returns:
            dict: A dictionary containing sugar type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'SugarType',
                'cu_off': self.cu_off,
                'ref': self.ref,
                })
        return d

class PointerType(SugarType):
    """Stores DWARF information for a pointer type."""
    def __init__(self, name, cu_off, target):
        """
        Initializes PointerType.

        Args:
            name (str): Type name.
            cu_off (int): Compilation Unit offset.
            target (int): DWARF offset of the type being pointed to.
        """
        SugarType.__init__(self, name, cu_off)
        self.ref = target

    def jsondump(self):
        """
        Prepares the pointer type info for JSON serialization.

        Returns:
            dict: A dictionary containing pointer type-specific and base attributes.
        """
        d = SugarType.jsondump(self)
        d.update({
                'tag': 'PointerType',
                })
        return d

class ArrayType(SugarType):
    """Stores DWARF information for an array type."""
    def __init__(self, name, cu_off, elemty):
        """
        Initializes ArrayType.

        Args:
            name (str): Type name.
            cu_off (int): Compilation Unit offset.
            elemty (int): DWARF offset of the array element type.
        """
        SugarType.__init__(self, name, cu_off)
        self.ref = elemty
        self.range = []

    def jsondump(self):
        """
        Prepares the array type info for JSON serialization.

        Returns:
            dict: A dictionary containing array type-specific and base attributes.
        """
        d = SugarType.jsondump(self)
        d.update({
                'tag': 'ArrayType',
                'range': self.range,
                })
        return d

class ArrayRangeType(SugarType):
    """Stores DWARF information for the size or bounds of an array dimension."""
    def __init__(self, name, cu_off, rtype, cnt):
        """
        Initializes ArrayRangeType.

        Args:
            name (str): Type name.
            cu_off (int): Compilation Unit offset.
            rtype (int): DWARF offset of the array index type.
            cnt (int): Array size/count.
        """
        SugarType.__init__(self, name, cu_off)
        self.ref = rtype
        self.size = cnt

    def jsondump(self):
        """
        Prepares the array range type info for JSON serialization.

        Returns:
            dict: A dictionary containing array range type-specific and base attributes.
        """
        d = SugarType.jsondump(self)
        d.update({
                'tag': 'ArrayRangeType',
                'size': self.size,
                })
        return d

class EnumType(TypeInfo):
    """Stores DWARF information for an enumeration type."""
    def __init__(self, name, size):
        """
        Initializes EnumType.

        Args:
            name (str): Enum name.
            size (int): Size of the enum in bytes.
        """
        TypeInfo.__init__(self, name)
        self.size = size

    def jsondump(self):
        """
        Prepares the enum type info for JSON serialization.

        Returns:
            dict: A dictionary containing enum type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'EnumType',
                'size': self.size,
                })
        return d

class SubroutineType(TypeInfo):
    """Stores DWARF information for a function type (signature)."""
    def __init__(self, name):
        """
        Initializes SubroutineType.

        Args:
            name (str): Subroutine type name.
        """
        TypeInfo.__init__(self, name)

    def jsondump(self):
        """
        Prepares the subroutine type info for JSON serialization.

        Returns:
            dict: A dictionary containing subroutine type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'SubroutineType',
                })
        return d

class UnionType(TypeInfo):
    """Stores DWARF information for a union type."""
    def __init__(self, name, cu_off, size):
        """
        Initializes UnionType.

        Args:
            name (str): Union name.
            cu_off (int): Compilation Unit offset.
            size (int): Size of the union in bytes.
        """
        TypeInfo.__init__(self, name)
        self.size = size
        self.cu_off = cu_off
        self.children = {}  # <member_offset: (name, type_offset)>

    def jsondump(self):
        """
        Prepares the union type info for JSON serialization.

        Returns:
            dict: A dictionary containing union type-specific and base attributes.
        """
        d = TypeInfo.jsondump(self)
        d.update({
                'tag': 'UnionType',
                'size': self.size,
                'cu_off': self.cu_off,
                'children': self.children,
                })
        return d

class Scope(object):
    """Represents a code range (e.g., function body, lexical block)."""
    def __init__(self, lopc, hipc):
        """
        Initializes Scope.

        Args:
            lopc (int): Low PC (start address).
            hipc (int): High PC (end address).
        """
        self.lowpc = lopc
        self.highpc = hipc

    def jsondump(self):
        """
        Prepares the scope info for JSON serialization.

        Returns:
            dict: A dictionary containing lowpc and highpc.
        """
        return {'lowpc': self.lowpc, 'highpc': self.highpc}

class LineRange(object):
    """Represents a contiguous range of addresses corresponding to a source line."""
    def __init__(self, lno, col, lopc, hipc, func):
        """
        Initializes LineRange.

        Args:
            lno (int): Line number.
            col (int): Column number.
            lopc (int): Low PC (start address).
            hipc (int): High PC (end address).
            func (int): Start address of the enclosing function.
        """
        self.lno = lno
        self.col = col
        self.lowpc = lopc
        self.highpc = hipc
        self.func = func

    def jsondump(self):
        """
        Prepares the line range info for JSON serialization.

        Returns:
            dict: A dictionary containing all line range attributes.
        """
        return {
                'lno': self.lno,
                'col': self.col,
                'lowpc': self.lowpc,
                'highpc': self.highpc,
                'func': self.func,
                }

def parse_dwarfdump(input_data: str, prefix: str=""):
    """
    The main parsing routine. Reads dwarfdump output, processes both line info
    and debug info sections, and populates the databases of variables, functions,
    and types. Finally, it dumps the databases to JSON files.

    Args:
        input_data (str): The content of the dwarfdump output.
        prefix (str, optional): Prefix for the output JSON filenames. Defaults to "".
    """
    reloc_base = 0
    line_info = LineDB()
    globvar_info = GlobVarDB()
    func_info = FunctionDB()
    type_info = TypeDB()

    data = parse_section(input_data)
    tag = ".debug_line"
    if tag in data:
        for line in data[tag]:
            if line is None:
                continue
            line = line.strip()
            if line.startswith("0x"):
                addrstr, rest = line.split('[')
                lnostr, info = rest.split(']')
                if "uri:" in info:
                    srcfn = info.split("uri:")[-1].strip()
                assert srcfn, "Source filename not found in line info"
                addr = int(addrstr.strip(), 16) + reloc_base
                lno = int(lnostr.strip().split(',')[0])
                col = int(lnostr.strip().split(',')[1])
                line_info.insert(srcfn, lno, col, addr)

    type_overlay = None
    cu_off = None
    lvl_stack = []
    scope_stack = []
    func_stack = []
    type_stack = []
    tag = ".debug_info"
    if tag in data:
        for line in data[tag]:
            line = line.strip()
            print(line)
            if not line:
                continue
            if not line.startswith('<'):
                continue

            die = line.split(' ')[0].strip()
            # Check for VALID DIE format
            if not (die.startswith('<') and die.endswith('>')):
                continue
            lvl, idx, tname = die[1:-1].split('><')
            lvl = int(lvl)

            res = parse_die(line)

            # If it's just a declaration, skip it. We want the actual code definition.
            if 'DW_AT_declaration' in res:
                if res['DW_AT_declaration'] == 'yes(1)':
                    continue

            if "DW_TAG_compile_unit" in line:
                assert 'DW_AT_low_pc' in res, "DW_AT_low_pc missing in compile unit"
                assert 'DW_AT_high_pc' in res, "DW_AT_high_pc missing in compile unit"
                base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                end_addr = int(res['DW_AT_high_pc'], 16) + reloc_base
                scope_stack = [Scope(base_addr, end_addr)]
                lvl_stack = [(lvl, 'DW_TAG_compile_unit')]
                func_stack = []
                type_stack = []
                cu_off = int(idx.split('+')[0], 16)
                continue

            idx = int(idx, 16)

            #print(lvl, idx, tname)

            while lvl < lvl_stack[-1][0]:
                lvl_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_lexical_block':
                    scope_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_subprogram':
                    # TODO: Verify if scope pop is needed here
                    # scope_stack.pop() # Added scope pop, AI recommendation...
                    func_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_structure_type':
                    type_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_union_type':
                    type_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_array_type':
                    type_stack.pop()

            if lvl != lvl_stack[-1][0] and lvl != (lvl_stack[-1][0]+1):
                continue

            if lvl_stack[-1][1] in ['SugarType', 'DW_TAG_pointer_type']:
                assert lvl == lvl_stack[-1][0], "Invalid level for type overlay"
                lvl_stack.pop()
                assert type_overlay, "Type overlay missing"
                type_overlay[2].ref = idx
                type_info.insert(type_overlay[0], type_overlay[1], type_overlay[2])
                type_overlay = None

            if tname == "DW_TAG_lexical_block":
                assert 'DW_AT_low_pc' in res, "DW_AT_low_pc missing in lexical block"
                assert 'DW_AT_high_pc' in res, "DW_AT_high_pc missing in lexical block"
                base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                end_addr = int(res['DW_AT_high_pc'], 16) + reloc_base
                scope_stack.append(Scope(base_addr, end_addr))
                lvl_stack.append((lvl, 'DW_TAG_lexical_block'))

            elif tname == "DW_TAG_variable":
                assert 'DW_AT_name' in res, "DW_AT_name missing in variable"
                name = res['DW_AT_name']
                v = VarInfo(name, cu_off)

                v.scope = scope_stack[-1]
                assert 'DW_AT_decl_line' in res, "DW_AT_decl_line missing in variable"
                v.decl_lno = int(res['DW_AT_decl_line'], 16)
                assert 'DW_AT_decl_file' in res, "DW_AT_decl_file missing in variable"
                v.decl_fn = res['DW_AT_decl_file']
                v.decl_fn = v.decl_fn[v.decl_fn.find(' ')+1:]
                if 'DW_AT_location' not in res:
                    continue
                for x in res['DW_AT_location'].split(':')[-1].strip().split('DW_OP_'):
                    x = x.strip()
                    if not x:
                        continue
                    v.loc_op.extend('DW_OP_{}'.format(x).split())
                v.loc_op = reprocess_ops(v.loc_op)
                assert 'DW_AT_type' in res, "DW_AT_type missing in variable"
                v.type = int(res['DW_AT_type'], 16)

                if len(func_stack) == 0:
                    globvar_info.insert(cu_off, v)
                else:
                    func_stack[-1].varlist.append(v)

            elif tname == "DW_TAG_formal_parameter":
                if 'DW_AT_name' not in res:
                    continue
                name = res['DW_AT_name']
                v = VarInfo(name, cu_off)

                v.scope = scope_stack[-1]
                assert 'DW_AT_decl_line' in res, "DW_AT_decl_line missing in formal parameter"
                v.decl_lno = int(res['DW_AT_decl_line'], 16)
                assert 'DW_AT_decl_file' in res, "DW_AT_decl_file missing in formal parameter"
                v.decl_fn = res['DW_AT_decl_file']
                v.decl_fn = v.decl_fn[v.decl_fn.find(' ')+1:]
                if 'DW_AT_location' not in res:
                    continue
                for x in res['DW_AT_location'].split(':')[-1].strip().split('DW_OP_'):
                    x = x.strip()
                    if not x:
                        continue
                    v.loc_op.extend('DW_OP_{}'.format(x).split())
                v.loc_op = reprocess_ops(v.loc_op)
                assert 'DW_AT_type' in res, "DW_AT_type missing in formal parameter"
                v.type = int(res['DW_AT_type'], 16)

                assert len(func_stack) > 0, "Formal parameter outside function"
                func_stack[-1].varlist.append(v)

            elif tname == "DW_TAG_subprogram":
                assert 'DW_AT_name' in res, "DW_AT_name missing in subprogram"
                name = res['DW_AT_name']

                assert 'DW_AT_low_pc' in res, "DW_AT_low_pc missing in subprogram"
                assert 'DW_AT_high_pc' in res, "DW_AT_high_pc missing in subprogram"
                base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                end_addr = int(res['DW_AT_high_pc'], 16) + reloc_base
                scope = Scope(base_addr, end_addr)
                scope_stack.append(scope)
                lvl_stack.append((lvl, 'DW_TAG_subprogram'))

                assert 'DW_AT_decl_file' in res, "DW_AT_decl_file missing in subprogram"
                if 'DW_AT_frame_base' in res:
                    fb_op = [res['DW_AT_frame_base'].split(':')[-1].strip()]
                else:
                    fb_op = []
                fb_op = reprocess_ops(fb_op)

                f = FuncInfo(cu_off, name, scope, fb_op)

                f.fn, f.lno = line_info.update_function(base_addr, end_addr, f)

                func_stack.append(f)
                func_info.insert(cu_off, f)

            elif tname == "DW_TAG_structure_type":
                if 'DW_AT_byte_size' in res:
                    sz = int(res['DW_AT_byte_size'], 16)
                else:
                    # It's a forward declaration. Set size to 0.
                    # 'None' is generally better as it indicates 'unknown size yet'.
                    sz = 0
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                t = StructType(name, cu_off, sz)

                type_info.insert(cu_off, idx, t)

                type_stack.append(t)
                lvl_stack.append((lvl, 'DW_TAG_structure_type'))

            elif tname == "DW_TAG_member":
                assert lvl_stack[-1][1] in ['DW_TAG_structure_type', 'DW_TAG_union_type'], "DW_TAG_member outside struct/union"

                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"

                # Skip bit fields
                if 'DW_AT_bit_size' in res or 'DW_AT_bit_offset' in res:
                    continue

                assert 'DW_AT_type' in res, "DW_AT_type missing in member"
                toff = int(res['DW_AT_type'], 16)

                assert 'DW_AT_data_member_location' in res, "DW_AT_data_member_location missing in member"
                loc_op = ['DW_OP_{}'.format(x.strip()) for x in \
                        res['DW_AT_data_member_location'].split(':')[-1].strip().split('DW_OP_')[1:]]
                # Signal attribute form DW_FORM_data1/2/4/8
                assert len(loc_op) == 1, "Complex location expressions in member not supported"
                assert loc_op[0].split()[0] == 'DW_OP_plus_uconst', "Only DW_OP_plus_uconst supported in member location"
                off = int(loc_op[0].split()[1])

                type_stack[-1].children[off] = (name, toff)

            elif tname == "DW_TAG_array_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                assert 'DW_AT_type' in res, "DW_AT_type missing in array type"
                elemoff = int(res['DW_AT_type'], 16)

                t = ArrayType(name, cu_off, elemoff)

                type_info.insert(cu_off, idx, t)

                lvl_stack.append((lvl, 'DW_TAG_array_type'))
                type_stack.append(t)

            elif tname == "DW_TAG_subrange_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                assert 'DW_AT_type' in res, "DW_AT_type missing in subrange type"
                toff = int(res['DW_AT_type'], 16)
                assert 'DW_AT_count' in res, "DW_AT_count missing in subrange type"
                cnt = int(res['DW_AT_count'], 16)
                # cnt = int(res['DW_AT_upper_bound'], 16)

                t = ArrayRangeType(name, cu_off, toff, cnt)

                type_info.insert(cu_off, idx, t)

                assert lvl_stack[-1][1] == 'DW_TAG_array_type', "DW_TAG_subrange_type outside array_type"
                assert (lvl_stack[-1][0]+1) == lvl, "Invalid level for subrange type"

                type_stack[-1].range.append(idx)

            elif tname == "DW_TAG_subroutine_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                t = SubroutineType(name)

                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_base_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                assert 'DW_AT_byte_size' in res, "DW_AT_byte_size missing in base type"
                sz = int(res['DW_AT_byte_size'], 16)
                t = BaseType(name, sz)

                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_pointer_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"

                if 'DW_AT_type' not in res:
                    lvl_stack.append((lvl, 'DW_TAG_pointer_type'))
                    type_overlay = (cu_off, idx, PointerType(name, cu_off, None))
                    continue
                target = int(res['DW_AT_type'], 16)

                t = PointerType(name, cu_off, target)

                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_enumeration_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"

                assert 'DW_AT_byte_size' in res, "DW_AT_byte_size missing in enumeration type"
                sz = int(res['DW_AT_byte_size'], 16)

                t = EnumType(name, sz)

                type_info.insert(cu_off, idx, t)

            elif tname in [
                    "DW_TAG_restrict_type",
                    "DW_TAG_const_type",
                    "DW_TAG_volatile_type",
                    "DW_TAG_typedef"
                    ]:
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                t = SugarType(name, cu_off)

                if 'DW_AT_type' not in res:
                    lvl_stack.append((lvl, 'SugarType'))
                    type_overlay = (cu_off, idx, t)
                    continue
                t.ref = int(res['DW_AT_type'], 16)

                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_union_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                assert 'DW_AT_byte_size' in res, "DW_AT_byte_size missing in union type"
                sz = int(res['DW_AT_byte_size'], 16)
                t = UnionType(name, cu_off, sz)

                type_info.insert(cu_off, idx, t)

                type_stack.append(t)
                lvl_stack.append((lvl, 'DW_TAG_union_type'))

            elif tname == "DW_TAG_ptr_to_member_type":
                name = res['DW_AT_name'] if 'DW_AT_name' in res else "void"
                t = PointerType(name, cu_off, None)
                type_info.insert(cu_off, idx, t)

            elif tname == "DW_TAG_imported_declaration":
                pass
            elif tname == "DW_TAG_unspecified_parameters":
                pass
            elif tname == "DW_TAG_constant":
                pass

    with open(prefix+'_lineinfo.json', 'w') as file:
        dump_json(file, line_info)
    with open(prefix+'_globvar.json', 'w') as file:
        dump_json(file, globvar_info)
    with open(prefix+'_funcinfo.json', 'w') as file:
        dump_json(file, func_info)
    with open(prefix+'_typeinfo.json', 'w') as file:
        dump_json(file, type_info)

def dump_json(j, info):
    """
    Utility function to serialize a DWARF database object to a JSON file.

    It uses a custom encoder to call the 'jsondump' method on DWARF objects.

    Args:
        j (file object): The file stream to write JSON to.
        info (TypeDB, LineDB, etc.): The database object to serialize.
    """
    class DwarfJsonEncoder(json.JSONEncoder):
        def default(self, obj):
            if hasattr(obj, "jsondump"):
                return obj.jsondump()
            else:
                return json.JSONEncoder.default(self, obj)
    json.dump(info.jsondump(), j, cls=DwarfJsonEncoder, indent=4)


if __name__ == '__main__':
    """
    Usage (File): python3 dwarfdump.py dump.txt my_prefix
    Usage (Pipe): dwarfdump -dil bin | python3 dwarfdump.py my_prefix
    """
    import os

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dwarfdump_output_file | output_prefix> [output_prefix_if_file_used]")
        sys.exit(1)

    dwarf_content = None
    prefix = ""

    # Check if the first argument is an existing file
    if os.path.isfile(sys.argv[1]):
        with open(sys.argv[1], 'r', encoding='utf-8') as fd:
            print(f"[*] Reading dwarfdump output from file: {sys.argv[1]}")
            dwarf_content = fd.read()
        # If a file is provided, prefix is usually the second argument
        prefix = sys.argv[2] if len(sys.argv) > 2 else "output"
    else:
        # If not a file, assume it's a prefix, and we are reading from a pipe
        prefix = sys.argv[1]
        print(f"[*] Reading dwarfdump data from stdin (pipe mode)...")
        # Read from buffer to get bytes for the internal pandare .decode() call
        dwarf_content = sys.stdin.buffer.read().decode()

    if not dwarf_content:
        print("[-] Error: No DWARF data found.")
        sys.exit(1)

    try:
        print(f"[*] Processing DWARF for prefix: {prefix}...")
        parse_dwarfdump(dwarf_content, prefix)
        print(f"[+] Success! JSON files generated with prefix '{prefix}'")
    except AssertionError as e:
        print("[-] Error: DWARF parsing failed (AssertionError).")
        print("    Try recompiling your guest binary with -O0 -g -gdwarf-2")
        print(f"   Full stack trace: {e}")
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
