from .ffi_importer import ffi


class volatility_mixins():
    '''
    Constructs a file and file handler that volatility can't ignore to back by PANDA physical memory
    '''

    def make_panda_file_handler(self, debug=False):
        from urllib.request import BaseHandler
        if 'PandaFileHandler' in globals():  # alread initialized
            return
        panda = self

        class PandaFile(object):
            def __init__(self, length, panda):
                self.pos = 0
                self.length = length
                self.closed = False
                self.mode = "rb"
                self.name = "/tmp/panda.panda"
                self.panda = panda
                self.classname = type(self).__name__

            def readable(self):
                return self.closed

            def read(self, size=1):
                if self.panda.bits == 32 and self.panda.arch == "i386":
                    data = self.panda.physical_memory_read(
                        self.pos & 0xfffffff, size)
                else:
                    data = self.panda.physical_memory_read(self.pos, size)
                if debug:
                    print(self.classname+": Reading " +
                          str(size)+" bytes from "+hex(self.pos))
                self.pos += size
                return data

            def peek(self, size=1):
                return self.panda.physical_memory_read(self.pos, size)

            def seek(self, pos, whence=0):
                if whence == 0:
                    self.pos = pos
                elif whence == 1:
                    self.pos += pos
                else:
                    self.pos = self.length - pos
                if self.pos > self.length:
                    print(self.classname+": We've gone off the deep end")
                if debug:
                    print(self.classname+" Seeking to address "+hex(self.pos))

            def tell(self):
                return self.pos

            def close(self):
                self.closed = True

        class PandaFileHandler(BaseHandler):
            def default_open(self, req):
                if 'panda.panda' in req.full_url:
                    length = panda.libpanda.ram_size
                    if length > 0xc0000000:
                        length += 0x40000000  # 3GB hole
                    if debug:
                        print(type(self).__name__ +
                              ": initializing PandaFile with length="+hex(length))
                    return PandaFile(length=length, panda=panda)
                else:
                    return None

            def file_close(self):
                return True

        globals()["PandaFileHandler"] = PandaFileHandler

    def get_volatility_symbols(self, debug=False):
        from .volatility_cli_classes import CommandLineMoreEfficient
        from volatility.framework import contexts
        from volatility.framework.layers.linear import LinearlyMappedLayer
        from volatility.framework.automagic import linux
        if "linux" in self.os_type:
            if not hasattr(self, "_vmlinux"):
                self.make_panda_file_handler(debug=debug)
                constructed_original = CommandLineMoreEfficient().run()
                linux.LinuxUtilities.aslr_mask_symbol_table(
                    constructed_original.context, constructed_original.config['vmlinux'], constructed_original.config['primary'])
                self._vmlinux = contexts.Module(
                    constructed_original.context, constructed_original.config['vmlinux'], constructed_original.config['primary'], 0)
            else:
                LinearlyMappedLayer.read.cache_clear()  # smearing technique
            return self._vmlinux
        else:
            print("Unsupported.")
            return None

    def run_volatility(self, plugin, debug=False):
        from .volatility_cli_classes import CommandLineRunFullCommand, StringTextRenderer
        self.make_panda_file_handler(debug=debug)
        cmd = CommandLineRunFullCommand().run("-q -f panda.panda " + plugin)
        output = StringTextRenderer().render(cmd.run())
        return output
