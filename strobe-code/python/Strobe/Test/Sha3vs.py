"""
SHA-3 and SHAKE test vectors

Copyright (c) Mike Hamburg, Cryptography Research, 2016.

I will need to contact legal to get a license for this; in the mean time it is
for example purposes only.
"""

from __future__ import print_function
import binascii
import sys
import getopt
import Strobe.Keccak
import fileinput


def monte(hash,seed,samples=100,iterations=1000,bits=None,
            minoutbits=None,maxoutbits=None,**kwargs):
    if bits is None and hash().out_bytes is not None:
        bits = hash().out_bytes * 8
    
    md = binascii.unhexlify(seed)
    inputlen = len(md)

    print()
    if maxoutbits is None:
        outputlen = minoutbytes = maxoutbytes = bits//8
        print("[L = %d]" % bits)
        mdname = "MD"
        print()
        print("Seed = %s" % seed)
    else:
        minoutbytes = (minoutbits+7)//8
        maxoutbytes = maxoutbits//8
        outputlen = maxoutbytes
        print("[Minimum Output Length (bits) = %d]" % minoutbits)
        print()
        print("[Maximum Output Length (bits) = %d]" % maxoutbits)
        mdname = "Output"
        print()
        print("Msg = %s" % seed)

    print()
    
    for j in range(samples):
        for i in range(iterations):
            md = hash.hash((md+bytearray(inputlen))[0:inputlen],length=outputlen)
            randmd = bytearray(2)+md
            randish = randmd[-2]*256 + randmd[-1]
            rng = maxoutbytes-minoutbytes+1
            prev_outputlen = outputlen
            outputlen = minoutbytes + (randish % rng)
            
        print("COUNT = %d" % j)
        if minoutbytes != maxoutbytes: print("Outputlen = %d" % (prev_outputlen*8))
        print(mdname,"=", "".join(("%02x" % x for x in md)))
        print()
        sys.stdout.flush()

def kat(hash,file,len=None,**kwargs):
    length = None
    outlen = None
    
    ignore = ["[Tested", "[Input Length", "COUNT = ",
        "[Minimum Output Length", "[Maximum Output Length"]
    
    for line in open(file,'r').readlines():
        line = line.rstrip()
        
        if line == "":
            print()
        elif any((line.startswith(ign) for ign in ignore)):
            print(line)
        elif line.startswith("Len = "):
            length = int(line.split("Len = ")[1])
            print(line)
        elif line.startswith("Msg = "):
            msg = line.split("Msg = ")[1]
            msg = binascii.unhexlify(msg)
            if length is not None: msg = msg[0:length//8]
            print(line)
        elif line.startswith("[L = "):
            outlen = int(line.split("[L = ")[1][0:-1])//8
            print(line)
        elif line.startswith("[Outputlen = "):
            outlen = int(line.split("[Outputlen = ")[1][0:-1])//8
            print(line)
        elif line.startswith("Outputlen = "):
            outlen = int(line.split("Outputlen = ")[1])//8
            print(line)
        elif line.startswith("Output = "):
            output = hash.hash(msg, length=outlen)
            print("Output =", "".join(("%02x" % x for x in output)))
        elif line.startswith("MD = "):
            output = hash.hash(msg, length=outlen)
            print("MD =", "".join(("%02x" % x for x in output)))
            
if __name__ == '__main__':
    
    def usage(err=1):
        print("usage: TODO", file=sys.stderr)
        exit(err)
    
    opts,args = getopt.getopt(sys.argv[1:], "", 
        ["test=","hash=","seed=","min-len=","max-len=","file="])
    if len(args) != 0 or len(opts) != len(set(opts)): usage()
    opts = dict(opts)
    
    hashes = {
        "SHA3_224":Strobe.Keccak.SHA3_224,
        "SHA3_256":Strobe.Keccak.SHA3_256,
        "SHA3_384":Strobe.Keccak.SHA3_384,
        "SHA3_512":Strobe.Keccak.SHA3_512,
        "SHAKE128":Strobe.Keccak.SHAKE128,
        "SHAKE256":Strobe.Keccak.SHAKE256
    }
    if "--hash" in opts and opts["--hash"] in hashes:
        hash = hashes[opts["--hash"]]
    else: usage()
    
    tests = {
        "Monte":monte,
        "Kat":kat
        # TODO: varlen
    }
    if "--test" in opts and opts["--test"] in tests:
        test = tests[opts["--test"]]
    else: usage()
    
    seed = None
    if "--seed" in opts: seed=opts["--seed"]
    
    file = None
    if "--file" in opts: file=opts["--file"]
    
    # parse lengths
    minlen = maxlen = None
    if "--min-len" in opts and opts["--min-len"] != "":
        minlen = int(opts["--min-len"])
    if "--max-len" in opts and opts["--max-len"] != "":
        maxlen = int(opts["--max-len"])
    if (minlen is None) != (maxlen is None): usage()
    if minlen is not None and (minlen+7)//8 > maxlen//8: usage()
    
    test(hash,seed=seed,file=file,minoutbits=minlen,maxoutbits=maxlen)

        
    
