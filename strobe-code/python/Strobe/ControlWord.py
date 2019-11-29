from collections import namedtuple

# Control flags
FLAG_R = 1<<0
FLAG_I = 1<<0
DIR_CLIENT = 0
DIR_SERVER = FLAG_I
FLAG_A = 1<<1
FLAG_C = 1<<2
FLAG_T = 1<<3
FLAG_M = 1<<4
FLAG_K = 1<<5

# Record defining a STROBE control word
class ControlWord(namedtuple("ControlWord",("name",
    "bytes","dmode","cmode",
    "length_bytes","length","max_length","min_length"))):

    """
    Control word for STROBE.
    
    TODO: write more docs
    """
    
    def __new__(cls,name,
        bytes,dmode,cmode=None,
        length_bytes=0,length=None,max_length=None,min_length=None,explicit=None):
        
        if explicit is None:
            explicit = (len(bytes) or length_bytes) and (dmode & FLAG_T)
        
        if cmode is None:
            # Default: Don't send unless there are length bytes and transport
            if explicit: cmode = FLAG_A | FLAG_T | FLAG_M
            else: cmode = FLAG_A | FLAG_M
        
        bytes = bytearray(bytes)
        if dmode & (FLAG_T | FLAG_A) == 0 and length_bytes == 0 and length is None:
            length = 0
        
        return super(ControlWord,cls).__new__(cls,name,
            bytes,dmode,cmode,
            length_bytes,length,max_length,min_length)
    
    def __str__(self): return self.name

TYPE_META      = 0
TYPE_ABSORB    = FLAG_A
TYPE_PLAINTEXT = FLAG_A | FLAG_T
TYPE_ENCRYPT   = FLAG_A | FLAG_T | FLAG_C
TYPE_MAC       =          FLAG_T | FLAG_C
TYPE_PRNG      = FLAG_A          | FLAG_C
TYPE_RATCHET   =                   FLAG_C # to be used with extract
TYPE_KEY       = FLAG_A          | FLAG_C
    
################################################################################
# Example control words.
#
# The STROBE lite framework is not tied to any of these definitions.
# These are just some examples / recommendations of what you can use.
#
# These code words span the gamut from offline encrypted and/or signed messages,
# to full TLS-like protocols.
#
# ***
# The assumption is that most protocols will use a VERY SMALL SUBSET of these tags.
# They are comprehensive just to demonstrate that you could replace TLS with a
# protocol like this.
# ***
################################################################################

# 0x00-0x0F: symmetric cryptography
SYM_SCHEME     = ControlWord("SYM_SCHEME",      [0x00], TYPE_PLAINTEXT , length_bytes=2)
SYM_KEY        = ControlWord("SYM_KEY",         [0x01], TYPE_KEY       )
APP_PLAINTEXT  = ControlWord("APP_PLAINTEXT",   [0x02], TYPE_PLAINTEXT , length_bytes=2)
APP_CIPHERTEXT = ControlWord("APP_CIPHERTEXT",  [0x03], TYPE_ENCRYPT   , length_bytes=2)
AUTH_DATA      = ControlWord("NONCE",           [0x04], TYPE_PLAINTEXT , length_bytes=2)
AUTH_DATA      = ControlWord("AUTH_DATA",       [0x05], TYPE_PLAINTEXT , length_bytes=2)
MAC            = ControlWord("MAC",             [0x06], TYPE_MAC       , length_bytes=2, length=16, explicit=False )
STEG_MAC       = ControlWord("STEG_MAC",        [0x06], TYPE_MAC       , length_bytes=2, min_length=16, cmode=TYPE_ENCRYPT|FLAG_M)
SIV_MAC_INNER  = ControlWord("SIV_MAC_INNER",   [0x06], TYPE_MAC       , length_bytes=2, length=16, explicit=False )
HASH           = ControlWord("HASH",            [0x07], TYPE_PRNG      , length_bytes=2, explicit=False )
SIV_PT_INNER   = ControlWord("SIV_PT_INNER",    [0x0D], TYPE_PLAINTEXT , explicit=False)
SIV_MAC_OUTER  = ControlWord("SIV_MAC_OUTER",   [0x0E], TYPE_PLAINTEXT , length=16)
RATCHET        = ControlWord("RATCHET",         [0x0F], TYPE_RATCHET   , length=32)

# 0x10-0x1F: Asymmetric key exchange and encryption */
KEM_SCHEME     = ControlWord("KEM_SCHEME",      [0x10], TYPE_PLAINTEXT , length_bytes=2)
PUBLIC_KEY     = ControlWord("PUBLIC_KEY",      [0x11], TYPE_PLAINTEXT , length_bytes=2)
KEM_EPH        = ControlWord("KEM_EPH",         [0x12], TYPE_PLAINTEXT , length_bytes=2)
KEM_RESULT     = ControlWord("KEM_RESULT",      [0x13], TYPE_KEY       )

# 0x18-0x1F: Signatures */
SIG_SCHEME     = ControlWord("SIG_SCHEME",      [0x18], TYPE_PLAINTEXT , length_bytes=2)
SIG_EPH        = ControlWord("SIG_EPH",         [0x19], TYPE_PLAINTEXT , length_bytes=2)
SIG_CHALLENGE  = ControlWord("SIG_CHALLENGE",   [0x1A], TYPE_PRNG      , length_bytes=2, explicit=False)
SIG_RESPONSE   = ControlWord("SIG_RESPONSE",    [0x1B], TYPE_ENCRYPT   , length_bytes=2)

# 0x00-0x0F: header and other metadata */
HANDSHAKE      = ControlWord("HANDSHAKE",       [0x20], TYPE_PLAINTEXT , length_bytes=2)
VERSION        = ControlWord("VERSION",         [0x21], TYPE_PLAINTEXT , length_bytes=2)
CIPHERSUITE    = ControlWord("CIPHERSUITE",     [0x22], TYPE_PLAINTEXT , length_bytes=2)
META_PLAINTEXT = ControlWord("META_PLAINTEXT",  [0x24], TYPE_PLAINTEXT , length_bytes=2)
META_CIPHERTEXT= ControlWord("META_CIPHERTEXT", [0x25], TYPE_PLAINTEXT , length_bytes=2)
CERTIFICATE    = ControlWord("CERTIFICATE",     [0x26], TYPE_PLAINTEXT , length_bytes=2)
ENCRYPTED_CERT = ControlWord("ENCRYPTED_CERT",  [0x27], TYPE_ENCRYPT   , length_bytes=2)
OVER           = ControlWord("OVER",            [0x2E], TYPE_MAC       , length_bytes=2)
CLOSE          = ControlWord("CLOSE",           [0x2F], TYPE_MAC       , length_bytes=2)
