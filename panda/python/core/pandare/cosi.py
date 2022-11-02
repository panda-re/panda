# TODO: rename to cosi
COSI = 'osi2'

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
        name = self.panda.ffi.string(name_ptr)
        self.panda.plugins[COSI].free_osi2_string(name_ptr)

        return name

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
        name = self.panda.ffi.string(name_ptr)
        self.panda.plugins[COSI].free_osi2_string(name_ptr)

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
