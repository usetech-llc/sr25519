"""
Keccak and Keccak modes.

Copyright (c) Mike Hamburg, Cryptography Research, 2016.
I will need to contact legal to get a license for this; in the mean time it is
for testing purposes only.
"""

import itertools
import unittest
from math import log

class KeccakError(Exception):
    pass

class KeccakF(object):
    """Keccak-f[n] on byte arrays."""
    def __init__(self,bits=1600,trace=False):
        """
        Initialize at a given bit length.
        If trace is set, then print out call,delta,return when called.
        """
        if bits not in [200,400,800,1600]:
            raise KeccakError("KeccakF bits must be in [200,400,800,1600]")
        self.bits = bits
        self.nbytes = bits//8
        self._trace = trace
        self._last = None
    
    def __repr__(self): return "KeccakF(%d)" % self.bits
    
    def copy(self):
        """Copy this F object"""
        ret = KeccakF(bits=self.bits,trace=self._trace)
        if self._last is not None: ret._last = bytearray(self._last)
        return ret
    
    def __call__(self, data):
        """Return KeccakF[n](data)"""
        if self._trace:
            if self._last is not None:
                print("Del  KeccakF:",\
                    "".join(("%02x" % (d^e) for d,e in zip(data,self._last))))
            print("Call KeccakF:", "".join(("%02x" % d for d in data)))
        
        WORD = self.bits//25
        A = [ [ sum(( data[(y*5+x)*WORD//8+o//8]<<o
                      for o in range(0,WORD,8)))
                for y in range(5)]
              for x in range(5)]
              
        def rot(x,n): return (x<<n | x>>(WORD-n)) & (1<<WORD)-1
        
        LFSR = 0x01
        B = [[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0]]
        for i in range(12 + 2*int(log(self.bits//25,2))):
            # Theta
            C = [ A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5) ]
            D = [ C[(x-1)%5] ^ rot(C[(x+1)%5],1) for x in range(5) ]
            for x in range(5):
                for y in range(5):
                    A[x][y] ^= D[x]

            # Rho pi
            x,y = 1,0
            for j in range(1,25):
                tmp = A[x][y]
                x,y = y,(2*x+3*y)%5
                B[x][y] = rot(tmp, (j*(j+1)//2) % WORD)
            B[0][0] = A[0][0]

            # Chi
            for x in range(5):
                for y in range(5):
                    A[x][y] = B[x][y]^((~B[(x+1)%5][y]) & B[(x+2)%5][y])

            # Iota
            for l in range(7):
                A[0][0] ^= ((1<<WORD)-1) & ((LFSR&1)<<(2**l-1))
                LFSR = (LFSR<<1) ^ (LFSR>>7)*0x171
            
        ret =  bytearray(( A[x][y]>>o & 0xFF
                   for y in range(5)
                   for x in range(5)
                   for o in range(0,WORD,8) ))
        
        
        if self._trace:
            self._last = bytearray(ret)
            print("Ret  KeccakF:", "".join(("%02x" % d for d in ret)))
                   
        return ret

class KeccakHash(object):
    """
    Keccak mode such as SHA3, SHAKE, cSHAKE, CMAC, etc
    """
    def __init__(self,rate_bytes=None,suffix=None,
                    S=bytearray(), # distinguisher 
                    N=bytearray(), # NIST function name
                    prefix=bytearray(),
                    out_bytes=None,F=None,
                    copy_of=None):
        
        if copy_of is None:
            if F is None: F = KeccakF()
            self._F = F
        
            self._st = bytearray(F.nbytes)
        
            if rate_bytes is None and out_bytes is not None:
                # Like SHA-3
                rate_bytes = F.nbytes - 2*out_bytes
            elif rate_bytes is None:
                raise KeccakError("Need a rate")
            
            self._pos = 0
            self.rate_bytes = rate_bytes
            self.out_bytes = out_bytes
            if len(S) or len(N):
                if suffix is None: suffix = 0x4
                self.update(self._bytepad(self._encode_string(N)
                                        + self._encode_string(S)))
        
            if suffix is None: suffix = 0x1
            
            self._suffix = suffix
            self.update(prefix)
        
        else:
            self._F = copy_of._F.copy()
            self._st = copy_of._st.copy()
            self._pos = copy_of._pos
            self._suffix = copy_of._suffix
            
            # rate_bytes and out_bytes should be public, I guess?
            self.rate_bytes = copy_of.rate_bytes
            self.out_bytes = copy_of.out_bytes
            
    
    def copy(self):
        """Copy the state of the hash"""
        return KeccakHash(copy_of=self)
    
    @staticmethod
    def _encode_string(string):
        return (bytearray(KeccakHash._left_encode(8*len(string)))
                + bytearray(string))
    
    def update(self,string):
        """Update the hash with a new state"""
        for b in string:
            if isinstance(b,str): b = ord(b[0])
            self._st[self._pos] ^= b
            self._pos += 1
            if self._pos >= self.rate_bytes:
                self._pos = 0
                self._st = self._F(self._st)
    
    @staticmethod
    def _left_encode(n):
        output = []
        while n > 0 or len(output)==0:
            output = [int(n % 256)] + output
            n >>= 8
        return bytearray([len(output)] + output)
        
    def _bytepad(self,string):
        w = self.rate_bytes
        string = self._left_encode(w) + bytearray(string)
        extra = (w - (len(string) % w)) % w
        string = string + bytearray(extra)
        return string
    
    def digest_it(self):
        """
        Return the output of the hash, as an iterator.
        Does not modify or destroy the context.
        """
        assert self._pos < self.rate_bytes
        i = 0
        st = bytearray(self._st)
        st[self._pos] ^= self._suffix
        st[self.rate_bytes-1] ^= 0x80
        
        while True:
            if i % self.rate_bytes == 0: st = self._F(st)
            yield st[i % self.rate_bytes]
            i += 1
            if self.out_bytes is not None and i == self.out_bytes:
                return
    
    def digest(self,length=None):
        """
        Return [length] bytes of the output of the hash.
        Does not modify or destroy the context.
        If length and out_bytes are not defined, return an iterator.
        """
        if length is None and self.out_bytes is None:
            return self.digest_it()
        elif length is None:
            length = self.out_bytes
        elif self.out_bytes is None:
            pass
        elif self.out_bytes < length:
            raise KeccakError("Requested output is too long")
        return bytearray(itertools.islice(self.digest_it(),length))
        
    @classmethod
    def hash(cls,string,length=None,*args,**kwargs):
        """Output the hash of a string."""
        obj = cls(*args,**kwargs)
        obj.update(string)
        return obj.digest(length)
    
def KeccakMode(name,*args,**kwargs):
    """
    Keccak hasher with mode filled in
    """
    class Derived(KeccakHash):
        def __init__(self):
            super(Derived,self).__init__(*args,**kwargs)
        def copy(self): return Derived(copy_of=self)
    Derived.__name__ = name
    return Derived

SHA3_224 = KeccakMode("SHA3_224",out_bytes=224//8,suffix=6)
SHA3_256 = KeccakMode("SHA3_256",out_bytes=256//8,suffix=6)
SHA3_384 = KeccakMode("SHA3_384",out_bytes=384//8,suffix=6)
SHA3_512 = KeccakMode("SHA3_512",out_bytes=512//8,suffix=6)
SHAKE128 = KeccakMode("SHAKE128",rate_bytes=200-128//4,suffix=0x1F)
SHAKE256 = KeccakMode("SHAKE256",rate_bytes=200-256//4,suffix=0x1F)

def cSHAKE128(S,N=""):
    return KeccakMode("cSHAKE128",S=S,N=N,rate_bytes=200-128//4)
    
def cSHAKE256(S,N=""):
    return KeccakMode("cSHAKE256",S=S,N=N,rate_bytes=200-256/4)
    
class SimpleTestVectors(unittest.TestCase):
    def test(self):
        message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        self.assertEqual(SHA3_224.hash(message),
            "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33".decode("hex"))
        self.assertEqual(SHA3_256.hash(message),
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376".decode("hex"))
        self.assertEqual(SHA3_384.hash(message),
            "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22".decode("hex"))
        self.assertEqual(SHA3_512.hash(message),
            ("04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d"
            +"ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e").decode("hex"))
        self.assertEqual(SHAKE128.hash(message,128/4),
            "1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5".decode("hex"))
        self.assertEqual(SHAKE256.hash(message,256/4),
            ("4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e3329"
            +"40d8688a4e6a59aa8060f1f9bc996c05aca3c696a8b66279dc672c740bb224ec").decode("hex"))
        self.assertEqual(cSHAKE128("Email Signature").hash(bytearray((i for i in xrange(0x04))),32),
            "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5".decode("hex"))
        self.assertEqual(cSHAKE128("Email Signature").hash(bytearray((i for i in xrange(0xc8))),32),
            "c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b".decode("hex"))
            
        # TODO: test cSHAKE256; more vectors; Monte Carlo

        
