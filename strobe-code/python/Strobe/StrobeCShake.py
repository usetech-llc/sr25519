"""
Equivalent implementation of STROBE, based on CSHAKE.  Doesn't implement the
key tree. Designed to show that STROBE is equivalent to an instance of cSHAKE.

Copyright (c) Mike Hamburg, Cryptography Research, 2016.

I will need to contact legal to get a license for this; in the mean time it is
for example purposes only.
"""

from __future__ import absolute_import
from Strobe.Keccak import cSHAKE128
from Strobe.Strobe import AuthenticationFailed

class StrobeCShake(object):
    def __init__(self,proto,prim=cSHAKE128,copy_of=None):
        if copy_of is None:
            self.prim = prim("STROBEv1.0.2")
            self.st = self.prim()
            self.rate = self.st.rate_bytes - 2
            self.output = bytearray(self.rate)
            self.begin_off = 0
            self.dir = None
            self.proto = proto
            self.duplex(0x12,proto)
        
        else:
            self.rate,self.begin_off,self.dir,self.proto,self.st = \
                (copy_of.rate,copy_of.begin_off,copy_of.dir,
                 copy_of.proto,copy_of.st.copy())
            self.output = copy_of.output.copy()
            self.prim = copy_of.prim
    
    def __repr__(self):
        return "StrobeCShake(\"%s\",%s)" % (self.proto, repr(self.prim))
    
    def copy(self): return Strobe(None,copy_of=self)
    def deepcopy(self): return self.copy()
    
    def duplex(self,op,data,more=False,meta_op=0b10010,metadata=None):
        """
        STROBE main duplexing mode, as in Strobe.py
        """
        (I,A,C,T,M,K) = ((op>>i) & 1 for i in range(6))
        assert (op >= 0 and op <= 0x3F)
        assert not K # Unimplemented!
        
        def runF():
            padlen = len(self.output)
            self.st.update(bytearray([self.begin_off]))
            self.output = self.st.digest(self.rate)
            if padlen == 0:
                self.st.update([self.st.suffix ^ 0x80])
            else:
                self.st.update(
                    [self.st.suffix]+(padlen-1)*[0x00]+[0x80])
            self.begin_off = 0
        
        meta_out = bytearray(0)
        if not more:
            # Begin the operation.  First apply metadata if there is any
            if metadata is not None:
                if T and I and (meta_op & 0b1000):
                    # Receive data, so receive meta-op as well.
                    meta_op |= 0b1
                meta_out = self.duplex(meta_op,metadata)
            
            # Mark the beginning of the operation.
            self.st.update([self.begin_off])
            self.output = self.output[1:]
            self.begin_off = self.rate-len(self.output)
            if len(self.output) == 0: runF()
        
            # Mark the mode; if the mode uses cipher then run F
            if T and self.dir is None: self.dir = I
            adjDirOp = op ^ (self.dir if T else 0)
            self.st.update([adjDirOp])
            self.output = self.output[1:]
            if len(self.output) == 0 or C or K: runF()

        # Change to byte array
        data = bytearray(data)
        main_out = bytearray()
        
        # OK, this is the actual duplex routine
        while len(data):
            can_do = min(len(data), len(self.output))
            
            wrk = data[0:can_do]
            update_after = I or not T
            
            if not update_after: self.st.update(wrk)
            if C:
                for i in range(can_do):
                    wrk[i] ^= self.output[i]
            if update_after: self.st.update(wrk)
            
            main_out += wrk
            self.output = self.output[can_do:]
            data = data[can_do:]
            
            if len(self.output) == 0:
                runF()
        
        if (A and I) or (T and not I):
            return meta_out + main_out
            
        elif (I,T,A) == (True,True,False):
            # Check the MAC (or recv_zero, but don't do that)
            assert not more # Technically well-defined, but has a side channel
            any_data = 0
            for d in main_out: any_data |= d
            if d: raise Exception("MAC failed")
        
        # No data, but maybe there is metadata.
        return meta_out

    def ad      (self,data,   **kw): return self.duplex(0b0010,data,**kw)
    def key     (self,data,   **kw): return self.duplex(0b0110,data,**kw)
    def prf     (self,data,   **kw): return self.duplex(0b0111,data,**kw)
    def send_clr(self,data,   **kw): return self.duplex(0b1010,data,**kw)
    def recv_clr(self,data,   **kw): return self.duplex(0b1011,data,**kw)
    def send_enc(self,data,   **kw): return self.duplex(0b1110,data,**kw)
    def recv_enc(self,data,   **kw): return self.duplex(0b1111,data,**kw)
    def send_mac(self,data=16,**kw): return self.duplex(0b1100,data,**kw)
    def recv_mac(self,data   ,**kw): return self.duplex(0b1101,data,**kw)
    def ratchet (self,data=32,**kw): return self.duplex(0b0100,data,**kw)
