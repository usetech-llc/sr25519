"""
A wrapper around a C implementation of STROBE.

Copyright (c) Mike Hamburg, Cryptography Research, 2016.

I will need to contact legal to get a license for this; in the mean time it is
for example purposes only.
"""
from __future__ import absolute_import

from ctypes import *

from Strobe.Strobe import AuthenticationFailed,I,A,C,T,M,K # TODO

class CStrobe_Failed(Exception):
    """Thrown when a MAC fails, or some internal exception occurred."""
    pass

PATH = "../c/build/"
_libstrobe = CDLL(PATH+"libstrobe.so.1")

class CStrobe_Container(Array):
    _strobe_size = c_size_t.in_dll(_libstrobe,"strobe_abi_sizeof_strobe_s").value
    _type_ = c_ulong
    _length_ = int(1 + (_strobe_size-1)//sizeof(c_ulong))

_libstrobe.strobe_abi_overhead_for_transaction.argtypes = (c_uint32,)
_libstrobe.strobe_abi_overhead_for_transaction.restype = c_ssize_t

_libstrobe.strobe_abi_attach_buffer.argtypes = (CStrobe_Container,POINTER(c_ubyte),c_size_t)
_libstrobe.strobe_abi_attach_buffer.restype = None

_libstrobe.strobe_init.argtypes = (CStrobe_Container,POINTER(c_ubyte),c_size_t)
_libstrobe.strobe_init.restype = None 

_libstrobe.strobe_duplex.argtypes = (CStrobe_Container,c_uint32,POINTER(c_ubyte),c_size_t)
_libstrobe.strobe_duplex.restype = c_ssize_t

class CStrobe(object):
    def __init__(self, proto):
        self.container = CStrobe_Container()
        proto = self.bufferize(proto)
        _libstrobe.strobe_init(self.container,proto,sizeof(proto))
    
    @staticmethod
    def bufferize(data):
        return (c_ubyte * len(data))(*bytearray(data))
    
    def operate(self, flags, data, more=False, meta_flags=A|M, metadata=None):
        # TODO: test operate() with generated metadata
        meta_out = bytearray()
        if (not more) and (metadata is not None):
            meta_out = self.operate(meta_flags, metadata)
            
        if more: flags |= 1<<28
        
        if (flags & (I|T) != (I|T)) and (flags & (I|A) != A):
            # Operation takes no input
            assert isinstance(data,int)
            datalen = data
            data = None
        else:
            data = self.bufferize(data)
            datalen = len(data)
        
        if (flags & (I|A) != (I|A)) and (flags & (I|T) != T):
            # Operation produces no output
            output = None
            outputlen = 0
        else:
            oh = _libstrobe.strobe_abi_overhead_for_transaction(flags)
            output = (c_ubyte * (datalen + oh))()
            outputlen = sizeof(output)
           
        if flags & I:
            # On inbound, the output is app side
            a,alen,t,tlen = output,outputlen,data,datalen
        else:
            # On outbound, the output is transport side
            a,alen,t,tlen = data,datalen,output,outputlen
        
        _libstrobe.strobe_abi_attach_buffer(self.container,t,tlen)
        ret = _libstrobe.strobe_duplex(self.container,flags,a,alen)
        
        if (ret < 0): raise CStrobe_failed()
        if output is None: return meta_out
        else: return bytearray(output) + meta_out

    def ad      (self,data,   **kw): return self.operate(0b0010,data,**kw)
    def key     (self,data,   **kw): return self.operate(0b0110,data,**kw)
    def prf     (self,data,   **kw): return self.operate(0b0111,data,**kw)
    def send_clr(self,data,   **kw): return self.operate(0b1010,data,**kw)
    def recv_clr(self,data,   **kw): return self.operate(0b1011,data,**kw)
    def send_enc(self,data,   **kw): return self.operate(0b1110,data,**kw)
    def recv_enc(self,data,   **kw): return self.operate(0b1111,data,**kw)
    def send_mac(self,data=16,**kw): return self.operate(0b1100,data,**kw)
    def recv_mac(self,data   ,**kw): return self.operate(0b1101,data,**kw)
    def ratchet (self,data=32,**kw): return self.operate(0b0100,data,**kw)

