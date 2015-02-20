#!/usr/bin/python

import volatility.addrspace as addrspace
import urllib
import socket
import struct
import sys

class PMemAddressSpace(addrspace.BaseAddressSpace):
    # PMemAccess request types
    REQ_OUIT = 0
    REQ_READ = 1
    REQ_WRITE = 2

    def __init__(self, base, config, **kwargs):
        '''
        Initializes the address space with volatility and connects to the PMemAcess socket
        '''
        # Address space setup
        self.as_assert(base == None, "Must be first Address Space")
        addrspace.BaseAddressSpace.__init__(self, None, config, **kwargs)
        self.as_assert(config.LOCATION.startswith("file://"), 'Location is not of file scheme')

        # Connect to the socket
        self.sock_path = config.LOCATION[len("file://"):]
        print 'Connecting to: ' + self.sock_path
        self.sock_fd = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock_fd.connect(self.sock_path)
        except socket.error, msg:
            print >>sys.stderr, 'PMemAddressSpace: ' + str(msg)
            sys.exit(1)
        print 'SUCCESS: Connected to: ' + self.sock_path

    def close(self):
        '''
        Closes our socket and tells qemu to close its socket and thread
        XXX: Multiple connections are made, but not all of them are closed.
        '''
        try:
            self.sock_fd
        except AttributeError:
            return
        # Send quit message
        self.send_request(self.REQ_OUIT, 0, 0)
        self.sock_fd.close()

    def __del__(self):
      self.close()
   
    def send_request(self, req_type, req_addr, req_len):
      '''
      Sends a formatted request to PMemAccess
      '''
      self.sock_fd.send(struct.pack("=QQQ", req_type, req_addr, req_len))
 
    def __read_bytes(self, addr, length, pad):
        '''
        Reads data using PMemAccess
        '''
        memory = ''
        try:
            # Split the requests into smaller chunks
            block_length = 1024*4
            read_length = 0
            while read_length < length:
              # Send read request
              read_len = block_length
              if length-read_length < read_len:
                  read_len = length-read_length
              self.send_request(self.REQ_READ, addr+read_length, read_len)
              # Read the memory
              memory += self.sock_fd.recv(read_len)
              # Read and confirm result
              status = struct.unpack("=B", self.sock_fd.recv(1))[0]
              if status == 0:
                  raise AssertionError("PMemAddressSpace: READ of length " + 
                                       str(read_length) + '/' + str(length) +
                                       " @ " + hex(addr) + " failed.")
              read_length += read_len
        except AssertionError, e:
            print e
            memory = ''
        return memory

    def read(self, addr, length):
        return self.__read_bytes(addr, length, pad=False)

    def zread(self, addr, length):
        return self.__read_bytes(addr, length, pad=True)

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return True

    def write(self, addr, data):
        '''
        Writes data using PMemAccess
        '''
        try:
            length = len(data)
            # Send write request
            self.send_request(self.REQ_WRITE, addr, length)
            self.sock_fd.send(data)
            status = struct.unpack("=B", self.sock_fd.recv(1))[0]
            # Make sure it worked
            if status == 0:
                raise AssertionError("PMemAddressSpace: WRITE of length " + str(length) +
                                     " @ " + hex(addr) + " failed.")
        except AssertionError, e:
            print e
            return False
        return True
