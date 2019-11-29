"""
An example implementation of STROBE.  Doesn't include the key tree.

Copyright (c) Mike Hamburg, Cryptography Research, 2016.

I will need to contact legal to get a license for this; in the mean time it is
for example purposes only.
"""

from __future__ import absolute_import
from Strobe.Keccak import KeccakF

class AuthenticationFailed(Exception):
    """Thrown when a MAC fails."""
    pass

I,A,C,T,M,K = 1<<0, 1<<1, 1<<2, 1<<3, 1<<4, 1<<5
   
class Strobe(object):
    def __init__(self, proto, F = KeccakF(1600), security = 128, copy_of=None, doInit=True):
        if copy_of is None:
            self.pos = self.posbegin = 0
            self.I0 = None
            self.F  = F
            self.R  = F.nbytes - security//4

            # Domain separation doesn't use Strobe padding
            self.initialized = False
            self.st = bytearray(F.nbytes)
            domain = bytearray([1,self.R,1,0,1,12*8]) \
                   + bytearray("STROBEv1.0.2")
            if doInit: self._duplex(domain, forceF=True)
    
            # cSHAKE separation is done.
            # Turn on Strobe padding and do per-proto separation
            self.R -= 2
            self.initialized = True
            if doInit: self.operate(A|M, proto)
            
        else:
            self.R,self.pos,self.posbegin,self.I0,self.F = \
                (copy_of.R,copy_of.pos,copy_of.posbegin,copy_of.I0,
                 copy_of.F.copy())
            self.st = bytearray(copy_of.st)
    
    def copy(self): return Strobe(None,copy_of=self)
    def deepcopy(self): return self.copy()
 
    def _runF(self):
        if self.initialized:
            self.st[self.pos]   ^= self.posbegin
            self.st[self.pos+1] ^= 0x04
            self.st[self.R+1]   ^= 0x80
        self.st  = self.F(self.st)
        self.pos = self.posbegin = 0

    def _duplex(self, data, cbefore=False, cafter=False, forceF=False):
        assert not (cbefore and cafter)
    
        # Copy data, and convert string or int to bytearray
        # This converts an integer n to an array of n zeros
        data = bytearray(data)

        for i in range(len(data)):
            if cbefore: data[i] ^= self.st[self.pos]
            self.st[self.pos]   ^= data[i]
            if cafter:  data[i]  = self.st[self.pos]
        
            self.pos += 1
            if self.pos == self.R: self._runF()
    
        if forceF and self.pos != 0: self._runF()
        return data
          
    def _beginOp(self, flags):
        # Adjust direction information so that sender and receiver agree
        if flags & T:
            if self.I0 is None: self.I0 = flags & I
            flags ^= self.I0

        # Update posbegin
        oldbegin, self.posbegin = self.posbegin, self.pos+1
    
        self._duplex([oldbegin,flags], forceF = flags&(C|K))
    
    def operate(self, flags, data, more=False, meta_flags=A|M, metadata=None):
        """
        STROBE main duplexing mode.
        
        Op is a byte which describes the operating mode, per the STROBE paper.
        
        Data is either a string or bytearray of data, or else a length.  If it
        is given as a length, the data is that many bytes of zeros.
        
        If metadata is not None, first apply the given metadata in the given
        meta_op.
        
        STROBE operations are streamable.  If more is true, this operation
        continues the previous operation.  It therefore ignores metadata and
        doesn't use the beginOp code from the paper.
        
        Certain operations return data.  If an operation returns no data
        (for example, AD and KEY don't return any data), it returns the empty
        byte array.
        
        The meta-operation might also return data.  This is convenient for
        explicit framing (meta_op = 0b11010/0b11011) or encrypted explicit
        framing (meta_op = 0b11110/0b11111)
        
        If the operation is a MAC verification, this function returns the
        empty byte array (plus any metadata returned) on success, and throws
        AuthenticationFailed on failure.
        """
        assert not (flags & (K|1<<6|1<<7)) # Not implemented here
        meta_out = bytearray()
        if more:
            assert flags == self.cur_flags
        else:
            if metadata is not None:
                meta_out = self.operate(meta_flags, metadata)
            self._beginOp(flags)
            self.cur_flags = flags
    
        if (flags & (I|T) != (I|T)) and (flags & (I|A) != A):
            # Operation takes no input
            assert isinstance(data,int)

        # The actual processing code is just duplex
        cafter    = (flags & (C|I|T)) == (C|T)
        cbefore   = (flags & C) and not cafter
        processed = self._duplex(data, cbefore, cafter)
    
        # Determine what to do with the output.
        if (flags & (I|A)) == (I|A):
            # Return data to the application
            return meta_out + processed 
        
        elif (flags & (I|T)) == T:
            # Return data to the transport.
            # A fancier implementation might send it directly.
            return meta_out + processed 
            
        elif (flags & (I|A|T)) == (I|T):
            # Check MAC
            assert not more
            failures = 0
            for byte in processed: failures |= byte
            if failures != 0: raise AuthenticationFailed()
            return meta_out

        else:
            # Operation has no output data, but maybe output metadata
            return meta_out

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
