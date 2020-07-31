"""
Mixin to allow interaction with pyperipherals.
"""

from inspect import signature
from struct import pack_into

from .ffi_importer import ffi


class pyperipheral_mixins:
    """
    Pyperipherals are objects which handle mmio read/writes using the PANDA
    callback infrastructure.
    Under the hood, they use the cb_unassigned_io_read/cb_unassigned_io_write
    callbacks.
    A python peripheral itself is an object which exposes the following
    functions:
        write_memory(self, address, size, value)
        read_memory(self, address, size)
    And has at least the following attributes:
        address
        size

    One example for such a python object are avatar2's AvatarPeripheral.
    """

    def _addr_to_pyperipheral(self, address):
        """
        Returns the python peripheral for a given address, or None if no
        peripheral is registered for that address
        """

        for pp in self.pyperipherals:
            if pp.address <= address < pp.address + pp.size:
                return pp
        return None

    def _validate_object(self, object):
        # This function makes sure that the object exposes the right interfaces

        if not hasattr(object, "address") or not isinstance(object.address, int):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Missing or non-int `address` attribute"
                ).format(object.__repr__())
            )

        if not hasattr(object, "size") or not isinstance(object.size, int):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Missing or non-int `address` attribute"
                ).format(object.__repr__())
            )

        if not hasattr(object, "read_memory"):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Missing read_memory function"
                ).format(object.__repr__())
            )

        params = list(signature(object.read_memory).parameters)
        if params[0] != "address" or params[1] != "size":
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Invalid function signature for read_memory"
                ).format(object.__repr__())
            )

        if not hasattr(object, "write_memory"):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Missing write_memory function"
                ).format(object.__repr__())
            )

        params = list(signature(object.write_memory).parameters)
        if params[0] != "address" or params[1] != "size" or params[2] != "value":
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n"
                    "Invalid function signature for write_memory"
                ).format(object.__repr__())
            )

        # Ensure object is not overlapping with any other pyperipheral
        if (
            self._addr_to_pyperipheral(object.address) is not None
            or self._addr_to_pyperipheral(object.address + object.size) is not None
        ):
            raise RuntimeError(
                (
                    "Registering PyPeripheral %s failed:\n" "Overlapping memories!"
                ).format(object.__repr__())
            )

        return True

    def pyperiph_read_cb(self, cpu, pc, physaddr, size, val_ptr):
        pp = self._addr_to_pyperipheral(physaddr)
        if pp is None:
            return False

        val = pp.read_memory(physaddr, size)
        buf = ffi.buffer(val_ptr, size)

        fmt = "{}{}".format(self._end2fmt[self.endianness], self._num2fmt[size])

        pack_into(fmt, buf, 0, val)

        return True

    def pyperiph_write_cb(self, cpu, pc, physaddr, size, val):
        pp = self._addr_to_pyperipheral(physaddr)
        if pp is None:
            return False

        pp.write_memory(physaddr, size, val)
        return True

    def register_pyperipheral(self, object):
        """
        Registers a python peripheral, and the necessary attributes to the
        panda-object, if not present yet.
        """

        # if we are the first pyperipheral, register the pp-dict
        if not hasattr(self, "pyperipherals"):
            self.pyperipherals = []
            self.pyperipherals_registered_cb = False
            self._num2fmt = {1: "B", 2: "H", 4: "I", 8: "Q"}
            self._end2fmt = {"little": "<", "big": ">"}

        self._validate_object(object)

        if self.pyperipherals_registered_cb is False:
            self.register_callback(
                self.callback.unassigned_io_read,
                self.callback.unassigned_io_read(self.pyperiph_read_cb),
                "pyperipheral_read_callback",
            )

            self.register_callback(
                self.callback.unassigned_io_write,
                self.callback.unassigned_io_write(self.pyperiph_write_cb),
                "pyperipheral_write_callback",
            )

            self.pyperipherals_registered_cb = True

        self.pyperipherals.append(object)

    def unregister_pyperipheral(self, pyperiph):
        """
        deregisters a python peripheral.
        The pyperiph parameter can be either an object, or an address
        Returns true if the pyperipheral was successfully removed, else false.
        """

        if isinstance(pyperiph, int) is True:
            pp = self._addr_to_pyperipheral(pyperiph)
            if pp is None:
                return False
        else:
            if pyperiph not in self.pyperipherals:
                return False
            pp = pyperiph

        self.pyperipherals.remove(pp)

        # If we dont have any pyperipherals left, unregister callbacks
        if len(self.pyperipherals) == 0:
            self.disable_callback("pyperipheral_read_callback", forever=True)
            self.disable_callback("pyperipheral_write_callback", forever=True)
            self.pyperipherals_registered_cb = False
        return True
