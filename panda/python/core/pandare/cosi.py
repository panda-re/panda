# TODO: rename to cosi
COSI = 'osi2'

from dataclasses import dataclass

class VolatilitySymbol:
    '''
    A reference to an entry in the volatility symbol table
    '''

    def __init__(self, panda, raw_ptr):
        self.panda = panda
        self.inner = raw_ptr

    def addr(self) -> int:
        '''
        Get the address of the symbol in memory, accounting for KASLR
        '''

        return self.panda.plugins[COSI].addr_of_symbol(self.inner)

    def value(self) -> int:
        '''
        Get the raw value for the symbol from the volatility symbol table
        '''

        return self.panda.plugins[COSI].value_of_symbol(self.inner)

    def name(self) -> str:
        '''
        Get the name for the given symbol
        '''

        name_ptr = self.panda.plugins[COSI].name_of_symbol(self.inner)
        name = self.panda.ffi.string(name_ptr).decode('utf8')
        self.panda.plugins[COSI].free_osi2_str(name_ptr)

        return name

@dataclass
class VolatilityStructField:
    '''
    A single field in a volatility struct
    '''

    name: str
    offset: int
    type_name: str

class VolatilityStruct:
    '''
    A reference to a struct in the volatility symbol table
    '''

    def __init__(self, panda, raw_ptr):
        self.panda = panda
        self.inner = raw_ptr

    def __getitem__(self, item):
        if type(item) is int:
            name = self.get_field_by_index(item)
            if name:
                offset = self.offset_of_field(name)
                type_name = self.type_of_field(name)

                return VolatilityStructField(
                    name=name,
                    offset=offset,
                    type_name=type_name
                )
            else:
                raise IndexError("Index {item} is out of range of the length of the struct fields")
        elif type(item) is str:
            name = item
            offset = self.offset_of_field(name)
            type_name = self.type_of_field(name)

            return VolatilityStructField(
                name=name,
                offset=offset,
                type_name=type_name
            )
        else:
            raise Exception("Invalid type {type(item)} for indexing VolatilityStruct")

    def get_field_by_index(self, index: int) -> str:
        '''
        Return the name of the field at a given index, returning `None` past the end
        of the fields.
        '''

        field_name = self.panda.plugins[COSI].get_field_by_index(self.inner, index)

        if field_name == self.panda.ffi.NULL:
            return None
        else:
            return self.panda.ffi.string(field_name).decode('utf8')

    def name(self) -> str:
        '''
        Get the name of the given struct
        '''

        name_ptr = self.panda.plugins[COSI].name_of_struct(self.inner)
        name = self.panda.ffi.string(name_ptr).decode('utf8')
        self.panda.plugins[COSI].free_osi2_str(name_ptr)

        return name

    def offset_of_field(self, name: str) -> int:
        '''
        Get the offset of a given field from the field name
        '''

        name = name.encode('utf8')
        name = self.panda.ffi.new("char[]", name)
        return self.panda.plugins[COSI].offset_of_field(self.inner, name)

    def type_of_field(self, name: str) -> str:
        '''
        Get the type of a given field from the field name
        '''

        name = name.encode('utf8')
        name = self.panda.ffi.new("char[]", name)
        type_name = self.panda.plugins[COSI].type_of_field(self.inner, name)
        type_name = self.panda.ffi.string(type_name).decode('utf8')

        return type_name

    def size(self) -> int:
        '''
        Get the total size of the given struct in bytes
        '''

        return self.panda.plugins[COSI].size_of_struct(self.inner)

    def fields(self):
        '''
        Iterate over the fields of the structure, yielding tuples in the form of
        (offset, type, field_name)
        '''
        i = 0

        while True:
            field = self.get_field_by_index(i)

            if not field:
                break

            name = field
            offset = self.offset_of_field(field)
            type_name = self.type_of_field(field)

            yield (offset, type_name, name)

            i += 1

class VolatilityBaseType:
    '''
    A reference to a base type in the volatility symbol table
    '''

    def __init__(self, panda, raw_ptr):
        self.panda = panda
        self.inner = raw_ptr

    def name(self) -> str:
        '''
        Get the name for the given base type
        '''

        name_ptr = self.panda.plugins[COSI].name_of_base_type(self.inner)
        name = self.panda.ffi.string(name_ptr).decode('utf8')
        self.panda.plugins[COSI].free_osi2_str(name_ptr)

        return name

    def size(self) -> int:
        '''
        Get the size of the given base type in bytes
        '''

        return self.panda.plugins[COSI].size_of_base_type(self.inner)

    def is_signed(self) -> bool:
        '''
        Get whether an integer base type is signed or not
        '''

        return self.panda.plugins[COSI].is_base_type_signed(self.inner)

class Cosi:
    '''
    Object to interact with the `cosi` PANDA plugin. An instance can be foudn at
    `panda.cosi`, where `panda` is a `Panda` object.
    '''

    def __init__(self, panda):
        self.panda = panda

    def symbol_addr_from_name(self, name: str) -> int:
        '''
        Given a symbol `name`, return the address in memory where it is located,
        accounting for KASLR as needed.
        '''

        name = name.encode('utf8')
        name = self.panda.ffi.new("char[]", name)
        addr = self.panda.plugins[COSI].symbol_addr_from_name(name)
        return addr

    def symbol_value_from_name(self, name: str) -> int:
        '''
        Given a symbol `name`, return the corresponding value in the volatility symbol
        table, not accounting for KASLR.
        '''

        name = name.encode('utf8')
        name = self.panda.ffi.new("char[]", name)
        addr = self.panda.plugins[COSI].symbol_value_from_name(name)
        return addr

    def kaslr_offset(self):
        '''
        Get the KASLR offset for the given system
        '''

        cpu = self.panda.get_cpu()
        offset = self.panda.plugins[COSI].kaslr_offset(cpu)

        return offset

    def symbol_from_name(self, name: str) -> VolatilitySymbol:
        '''
        Get a reference to a given symbol given the name of the symbol
        '''

        name = name.encode('utf8')
        name = self.panda.ffi.new("char[]", name)
        symbol = self.panda.plugins[COSI].symbol_from_name(name)

        return VolatilitySymbol(self.panda, symbol)

    def base_type_from_name(self, name: str) -> VolatilityBaseType:
        '''
        Get a reference to a given base type from the volatility symbol table
        '''

        name = name.encode('utf8')
        name = self.panda.ffi.new("char[]", name)
        base_type = self.panda.plugins[COSI].base_type_from_name(name)

        return VolatilityBaseType(self.panda, base_type)

    def type_from_name(self, name: str) -> VolatilityStruct:
        '''
        Get a reference to a given struct from the volatility symbol table
        '''

        name = name.encode('utf8')
        name = self.panda.ffi.new("char[]", name)
        struct = self.panda.plugins[COSI].type_from_name(name)

        return VolatilityStruct(self.panda, struct)
