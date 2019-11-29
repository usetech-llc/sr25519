"""
An example implementation of STROBE.

The key tree may be patented.  Also, it may be easy to violate other
patents with this code, so be careful.

Copyright (c) Mike Hamburg, Cryptography Research, 2015-2016.

I will need to contact legal to get a license for this; in the mean time
it is for example purposes only.
"""
from .Keccak import KeccakF
from .ControlWord import *
from collections import namedtuple
import base64
import threading
import itertools


class StrobeException(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class AuthenticationFailed(StrobeException):
    def __init__(self,*args,**kwargs):
        StrobeException.__init__(self,*args,**kwargs)

class ProtocolError(StrobeException):
    def __init__(self,*args,**kwargs):
        StrobeException.__init__(self,*args,**kwargs)

def zeros():
    while True: yield 0

class Strobe(object):
    """
    STROBE protocol framework
    """
    version = "v0.7"
    PAD = 0x04
    CSHAKE_PAD = 0x80
    
    def __init__(self,proto,dir=None,F=None,rate=None,steg=0,copy_from=None,over_rate=None,doInit=True,verbose=False):
        if copy_from is not None:
            self.F = copy_from.F
            self.rate = copy_from.rate
            self.proto = copy_from.proto
            self.off = copy_from.off
            self.prev_mark = copy_from.prev_mark
            self.dir = copy_from.dir
            self.st = bytearray(copy_from.st)
            self.steg = copy_from.steg
            self.over_rate = copy_from.over_rate
            self.verbose = verbose
        
        else:
            if F is None: F = KeccakF()
            if rate is None: rate = F.nbytes - 32 - 2
            self.F = F
            self.rate = rate
            self.proto = proto
            self.off = self.prev_mark = 0
            self.dir = dir
            self.steg = steg
            self.over_rate = rate + 2
            self.verbose = verbose
            if doInit: self.init(proto,over_rate)
            else: self.st = bytearray(self.F.nbytes)
    
    def __str__(self):
        if self.dir is None: dir = "None"
        elif self.dir == DIR_CLIENT: dir = "DIR_CLIENT"
        elif self.dir == DIR_SERVER: dir = "DIR_SERVER"
        return "%s(%s,dir=%s,F=%s)" % (
            self.__class__.__name__,self.proto,dir,self.F
            )
    
    def copy(self):
        return Strobe(proto=self.proto,copy_from=self)

    def init(self,proto,over_rate=None):
        """
        The initialization routine sets up the state in a way that is
        unique to this Strobe protocol.  Unlike SHA-3, the protocol
        and rate are distinguished up front in the first call to the
        F-function.
        """
        self.st = bytearray(self.F.nbytes)
        
        # Initialize according to cSHAKE.  TODO: check that this is correct
        aString = "STROBE " + self.__class__.version
        cShakeD = bytearray([1,self.over_rate,1,len(aString)]) + aString + bytearray([1,0])
        self.st[0:len(cShakeD)] = cShakeD
        self.st = self.F(self.st)
        
        self.duplex(FLAG_A|FLAG_M,proto)
    
    def _run_f(self):
        """
        Pad out blocks and run the sponge's F-function
        """
        self.st[self.off] ^= self.prev_mark
        self.st[self.off+1] ^= self.PAD
        self.st[self.over_rate-1] ^= self.CSHAKE_PAD
        # if self.verbose:
        #     print "**** IN ****"
        #     print "".join(("%02x" % b for b in self.st))
        self.st = self.F(self.st)
        # if self.verbose:
        #     print "**** OU ****"
        #     print "".join(("%02x" % b for b in self.st))
        self.off = self.prev_mark = 0
    
    def _set_mode(self, mode):
        """
        Put a delimiter in the hash state.
        """
        self.st[self.off] ^= self.prev_mark
        self.off += 1
        self.prev_mark = self.off
        if self.off >= self.rate: self._run_f()
        
        # Adjust the mode for initiator vs responder
        if mode & FLAG_T:
            if self.dir is None:
                self.dir = mode & FLAG_I
            mode ^= self.dir
        
        self.st[self.off] ^= mode
        self.off += 1
        if self.off >= self.rate or (mode & (FLAG_C | FLAG_K)):
            self._run_f()
    
    def duplex(self,op,data=None,length=None,as_iter=False):
        """
        The main STROBE duplex operation.
        """
        # steg support: if would send/recv in the clear, send/recv encrypted instead.
        if op & FLAG_T: op |= self.steg
        self._set_mode(op)
        
        (I,T,C,A,K) = (bool(op & f) for f in [FLAG_I,FLAG_T,FLAG_C,FLAG_A,FLAG_K])
        if isinstance(data,str): data = bytearray(data)

        # compute flags
        yield_anything = (A and I) or (T and not I)
        read_anything = (T and I) or (A and not I)
        verify_mac = (I,T,A) == (True,True,False)
            
        if data is None or not read_anything:
            if length is None: data = ()
            else: data = zeros()

        if length is not None:
            data = itertools.islice(data,length)

        
        if self.verbose: print("Duplex mode=0x%02x:\n   " % op, end=' ')
        out = self._duplex_iter((I,T,A,C,K),data)
        
        if yield_anything:
            # Return the iterator
            if as_iter: return out
            return bytearray(out)
            
        elif verify_mac:
            # Asked to verify a MAC
            res = 0
            for o in out: res |= o
            if res: raise AuthenticationFailed()
            return ()
            
        else:
            # The data is not used
            for o in out: pass
            return ()
    
    def _duplex_iter(self, op, data):
        """
        Duplexing sponge construction, iterator-version.
        """
        (I,T,A,C,K) = op
        res = 0
        
        if C: s2o = 0x00FF
        else: s2o = 0
        s2s = 0xFFFF
        if T and not I: s2s ^= s2o
        
        if K:
            # The DPA-resistant key tree is a CRI design to mitigate differential
            # power analysis at a protocol level.
            if self.off != 0:
                # Since we call self.mark(C or K) above, this is only possible through
                # misuse of "more"
                raise Exception("Bug: user called keytree with off != 0")
                
            keytreebits = 2
            assert keytreebits > 0 and 8 % keytreebits == 0 and self.PAD << keytreebits < 256
            mask = (1<<keytreebits)-1
            s2o >>= 8-keytreebits
            s2s >>= 8-keytreebits
            
            for byte in data:
                for bpos in range(0,8,keytreebits):
                    byte ^= (self.st[0] & s2o) << bpos
                    self.st[0] &= s2s
                    self.st[0] ^= (byte >> bpos) & mask
                    self.st[1] ^= self.PAD<<keytreebits
                    self.st[self.over_rate-1] ^= self.CSHAKE_PAD
                    self.st = self.F(self.st)
                
                yield byte
        
        else:
            # Not the keytree
            for byte in data:
                if self.verbose: print("%02x" % byte, end=' ')
                byte ^= self.st[self.off] & s2o
                self.st[self.off] &= s2s
                self.st[self.off] ^= byte
            
                self.off += 1
                if self.off >= self.rate: self._run_f()
                
                yield byte
        if self.verbose: print()
                
    def begin_steg(self):
        """
        Begin steganography.
        """
        self.steg = FLAG_C

    @staticmethod
    def i2o_le(number,length):
        """
        Encode a non-negative integer to bytes, little-endian, of the given length.
        """
        if number < 0 or number >= 1 << (8*length):
            raise ProtocolError("Cannot encode number %d in %d bytes"
                % (number, length))
        return [ 0xFF & number >> (8*i)
                 for i in range(length) ]
    
    @staticmethod
    def o2i_le(enc_number):
        """
        Decode a non-negative integer from bytes, little-endian.
        """
        return sum(( int(x)<<(8*i) for (i,x) in enumerate(enc_number) ))
        
    def outbound(self,cw,data=(),length=None,**kwargs):
        """
        Send or inject data with the given control-word.
        """
        if length is not None and data is not ():
            raise ProtocolError("Explicit length set with data")
            
        if cw.length_bytes == 0:
            encoded_length = ()
            if length is None: length = cw.length
        else:
            # determine the length
            if length is None: length = cw.length
            if length is None:
                try: length = len(data)
                except TypeError:
                    data = bytearray(data)
                    length = len(data)
            
            # encode it
            encoded_length = self.i2o_le(length,cw.length_bytes)
        
        cw_bytes = itertools.chain(cw.bytes, encoded_length)
        s1 = self.duplex(cw.cmode, cw_bytes)
        s2 = self.duplex(cw.dmode, data, length=length, **kwargs)
        return bytearray(s1) + bytearray(s2)
        
    def send(self,cw,*args,**kwargs):
        """
        Same as .outbound, but assert that mode includes actually sending
        data to the wire.
        (It is possible that no data will be sent if the length is 0.)
        """
        if not (cw.dmode | cw.cmode) & FLAG_T:
            raise ProtocolError(
                "Used .send on non-T control word; use .inject or .outbound instead"
                )
        return self.outbound(cw,*args,**kwargs)
        
    def inject(self,cw,*args,**kwargs):
        """
        Same as .outbound, but assert that the mode does not include
        sending data to the wire.
        """
        if (cw.dmode | cw.cmode) & FLAG_T:
            raise ProtocolError(
                "Used .inject on T control word; use .send or .outbound instead"
                )
        self.outbound(cw,*args,**kwargs)
    
    def recv_cw(self,data,possible_cws):
        """
        Receive data from a list of possible keywords.
        Return the keyword and length, or throw an error.
        """
        # create stream data
        cm = FLAG_I|FLAG_A|FLAG_T|FLAG_M
        stream = self.duplex(cm,data,as_iter=True)
        
        poss = list(possible_cws)
        i = 0
        dr = []
        
        def can_begin_with(cw,bs):
            if len(bs) > len(cw.bytes) + cw.length_bytes: return False
            lencmp = min(len(bs),len(cw.bytes))
            return bytearray(cw.bytes[0:lencmp]) == bytearray(bs[0:lencmp])
            
        while len(poss) > 1:
            
            b = next(stream)
            dr.append(b)
            
            poss = [cw for cw in poss if can_begin_with(cw,dr)]

        if len(poss) == 0:
            # oops, eliminated all possibilities
            raise ProtocolError("None of the expected CWs received")
        
        # read extra bytes to finish the control word
        cw = poss[0]
        extra = len(cw.bytes) + cw.length_bytes - len(dr)
        dr.extend(itertools.islice(stream,extra))
        
        if cw.length_bytes > 0:
            actual_length = self.o2i_le(dr[-cw.length_bytes:])
            
            # Sanity-check length
            if cw.length is not None and cw.length != actual_length:
                raise ProtocolError("Received length %d doesn't matched expected length %d"
                        % (actual_length, cw.length))
            elif cw.min_length is not None and cw.min_length > actual_length:
                raise ProtocolError("Received length %d less than expected min-length %d"
                        % (actual_length, cw.min_length))
            elif cw.max_length is not None and cw.max_length < actual_length:
                raise ProtocolError("Received length %d greater than expected max-length %d"
                        % (actual_length, cw.max_length))
                
            return cw, actual_length
        
        else:
            return cw, cw.length
    
    def inbound_data(self,cw,data,**kwargs):
        """
        Take data from a connection.
        """
        mode = cw.dmode
        if mode & (FLAG_A | FLAG_T): mode |= FLAG_I
        return self.duplex(mode,data,**kwargs)
        
    def inbound(self,cws,data=(),length=None,return_cw=False):
        """
        Dual of outbound, except that you can pass multiple control words.
        """
        if isinstance(cws,ControlWord): cws = [cws]
        
        data = iter(data)
        if any((cw1.cmode & FLAG_T for cw1 in cws)):
            cw,length = self.recv_cw(data,cws)
        
        else:
            assert len(cws) == 1
            cw = cws[0]
            bytes = cw.bytes
            if length is None: length = cw.length
            if cw.length_bytes != 0:
                assert length is not None
                bytes = bytes + bytearray(self.i2o_le(length,cw.length_bytes))
            self.duplex(cw.cmode, bytes)
        
        # NB: This precludes use of a "PING" tag, where one party sends the tag
        # and the other party sends the data.  So if you're going to do that,
        # you'll need to call recv_cw and outbound separately.
        idata = self.inbound_data(cw,data,length=length)
        if return_cw: return cw,idata
        else: return idata

    def recv(self,cws,*args,**kwargs):
        """
        Same as .inbound, but assert that mode includes actually receiving
        data to the wire.
        """
        if isinstance(cws,ControlWord): cws = [cws]
        if not all(((cw.dmode | cw.cmode) & FLAG_T for cw in cws)):
            raise ProtocolError(
                "Used .recv on non-T control word; use .extract or .inbound instead"
                )
        return self.inbound(cws,*args,**kwargs)
        
    def extract(self,cw,*args,**kwargs):
        """
        Same as .inbound, but assert that the mode does not include
        receiving data from the wire.
        """
        if (cw.dmode | cw.cmode) & FLAG_T:
            raise ProtocolError(
                "Used .extract on T control word; use .recv or .inbound instead"
                )
        return self.inbound(cw,*args,**kwargs)
    
    def send_siv(self,msg):
        post = self.copy()
        msg1 = self.outbound(SIV_PT_INNER,msg)
        mac1 = self.outbound(SIV_MAC_INNER)
        mac2 = post.outbound(SIV_MAC_OUTER,mac1)
        msg2 = post.outbound(APP_CIPHERTEXT,msg1)
        return itertools.chain(mac2, msg2)
    
    def recv_siv(self,msg):
        post = self.copy()
        msg = iter(msg)
        mac1 = post.inbound(SIV_MAC_OUTER,msg)
        msg1 = post.inbound(APP_CIPHERTEXT,msg)
        msg0 = self.inbound(SIV_PT_INNER,msg1)
        self.inbound(SIV_MAC_INNER,mac1)
        return msg0
