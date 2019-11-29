"""
Concurrence tester.  Tests multiple implementations of the same thing.
Error if any of them errors, or if they give difference results.
"""

from __future__ import absolute_import

class ConcurrenceTestFailure(Exception):
    pass

class ConcurrenceTest(object):
    def __init__(self,*args):
        self.impls = list(args)
        assert(len(self.impls))
    
    def __repr__(self):
        print("ConcurrenceTest(%s)" % ",".join((g.repr for g in self.impls)))
    
    def __str__(self): return repr(self)

    def copy(self):
        return ConcurrenceTest(*[c.copy() for c in self.impls])
    
    def deepcopy(self): return self.copy()
    
    def __getattr__(self, name):
        """
        The main tester.  Run the call for each impl, and compare results.
        """
        def method(*args,**kwargs):
            have_any_ret = False
            accepted_ret = None
            
            for g in self.impls:
                try: ret = ("OK",getattr(g,name)(*args,**kwargs))
                except Exception as e: ret = ("EXN",e)
                
                if not have_any_ret:
                    accepted_ret = ret
                    
                have_any_ret = True
                if ret != accepted_ret:
                    raise ConcurrenceTestFailure(
                        "%s: %s\n%s: %s" %
                            (self.impls[0], accepted_ret, g, ret)
                    )
            
            if accepted_ret[0] == "OK": return accepted_ret[1]
            else: raise accepted_ret[1]
            
        return method
        
            
if __name__ == '__main__':
    from Strobe.Keccak import cSHAKE128, cSHAKE256
    from Strobe.StrobeCShake import StrobeCShake
    from Strobe.StrobeCWrapper import CStrobe
    from Strobe.Strobe import Strobe
    
    proto = "concurrence test"
    ct = ConcurrenceTest(Strobe(proto), StrobeCShake(proto), CStrobe(proto))
    ct.prf(10)
    ct.ad("Hello")
    ct.send_enc("World")
    ct.send_clr("foo")
    ct.recv_clr("bar")
    ct.recv_enc("baz")
    for i in xrange(200):
        ct.send_enc("X"*i)
    ct.prf(123)
    ct.send_mac()
    
    print "Concurrence test passed."
    