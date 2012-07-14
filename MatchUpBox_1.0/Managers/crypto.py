# MatchUpBox: a privacy preserving online social network.
# Copyright (C) 2012 MatchUpBox <http://www.matchupbox.com>

# This file is part of MatchUpBox.

# MatchUpBox is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation version 3 of the License.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# MatchUpBox certificate:
#   A) 20 byte [hex]: 160bit SHA1 ID
#   B) 182 bytes [PEM]: RSA 512 public key
#   C) 128 bytes [hex]: 512bit signature of (A+B) made with RSA 512bit private TIS key and SHA1

import sys, os
import hashlib
import hmac
import M2Crypto
import itertools
#imported for AES by andrea
import binascii
import cStringIO
from M2Crypto import m2

def createUId(name):
    # name = ('Name', 'Surname', ...)
    # create the 160-bit id (using HMAC and SHA1)
    # and return it in hex format

    kh = hmac.new("TIS KEY FOR USER ID", digestmod=hashlib.sha1)
    kh.update("-".join(name))
    return kh.digest()

def createNId(name):
    # name = ('Name', 'Surname', ...)
    # create the 160-bit id (using HMAC and SHA1)
    # and return it in hex format

    kh = hmac.new("TIS KEY FOR NODE ID", digestmod=hashlib.sha1)
    kh.update("-".join(name))
    return kh.digest()



#added by andrea
def generateKeyPair():
    # generate a random public key using RSA 512
    # return it in PEM format
    # save to PEM file both private and public key
    keys = M2Crypto.RSA.gen_key(512, 65537, lambda: None)
    return keys
def saveKeyPairs(keys,filename):
    keys.save_key('mypem'+os.sep+filename+'Keys.pem', None, lambda: None)
    keys.save_pub_key('mypem'+os.sep+filename+'PKey.pem')

def loadKeyPrivate(name):
    keys = M2Crypto.RSA.load_key("mypem"+os.sep+name+"Keys.pem")
    return keys
    	
	
def encrypt_AES(plaintext, skey, IV):
    binascii.b2a_hex(plaintext)
    k=M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=skey, iv=IV, op=1)
    pbuf=cStringIO.StringIO(plaintext)
    cbuf=cStringIO.StringIO()
    ciphertext = binascii.hexlify(__cipher_filter__(k, pbuf, cbuf))
    pbuf.close()
    cbuf.close()
    return ciphertext

def decrypt_AES(ciphertext, skey, IV):
    j=M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=skey, iv=IV, op=0)
    pbuf=cStringIO.StringIO()
    cbuf=cStringIO.StringIO(binascii.unhexlify(ciphertext))
    plaintext=__cipher_filter__(j, cbuf, pbuf)
    pbuf.close()
    cbuf.close()
    return plaintext
	
def createKeyPair(name):
    # generate a random public key using RSA 512
    # return it in PEM format
    # save to PEM file both private and public key
    keys = M2Crypto.RSA.gen_key(512, 65537, lambda: None)
    keys.save_key('mypem/'+name+'Keys.pem', None, lambda: None)
    keys.save_pub_key('mypem/'+name+'PKey.pem')

def createKeyPair2(name,prefix):
    # generate a random public key using RSA 512
    # return it in PEM format
    # save to PEM file both private and public key
    keys = M2Crypto.RSA.gen_key(512, 65537, lambda: None)
    keys.save_key(prefix+'mypem/'+name+'Keys.pem', None, lambda: None)
    keys.save_pub_key(prefix+'mypem/'+name+'PKey.pem')
def loadKeyPair(name):
    # return a M2Crypto.RSA.RSA object
    keys = M2Crypto.RSA.load_key('mypem/'+name+'Keys.pem', lambda: None)
    return keys
    
def loadPublicKey(name):
    # return the Public Key as a strig in pem format
    f = open('mypem'+os.sep+name+'PKey.pem')
    pkey = f.read()
    f.close()
    return pkey
#not necessary in final version
def tis_sign(data):
    # sign the ID and public key with TIS private key
    # return the signature in hex format
    keys = M2Crypto.RSA.load_key("mypem/TISKeys.pem", lambda: None)
    dgst = M2Crypto.EVP.MessageDigest('sha1')
    dgst.update(data)
    return keys.sign(dgst.digest(), 'sha1')

def sign(keys, data):
    dgst = M2Crypto.EVP.MessageDigest('sha1')
    dgst.update(data)
    return keys.sign(dgst.digest(), 'sha1')

def verify_tis_sign(data, sign):
    pubkey = loadPublicKey("TIS")
    bio = M2Crypto.BIO.MemoryBuffer(pubkey)
    rsa = M2Crypto.RSA.load_pub_key_bio(bio)
    dgst = M2Crypto.EVP.MessageDigest('sha1')
    dgst.update(data)
    try:
        rsa.verify(dgst.digest(), sign, 'sha1')
    except:
        return False
    return True
    
def verify_tis_cert(cert):
    data = cert[0] + cert[1]
    sign = cert[2]
    return verify_tis_sign(data, sign) 
        
def verify_sign(pkey, data, sign):
    try:
        bio = M2Crypto.BIO.MemoryBuffer(pkey)
        rsa = M2Crypto.RSA.load_pub_key_bio(bio)
        dgst = M2Crypto.EVP.MessageDigest('sha1')
        dgst.update(data)
        rsa.verify(dgst.digest(), sign, 'sha1')
    except:
        return False
    return True
#not necessary in final version
def genDHTlkeys(name):          
    return [hashlib.sha1("".join(x).lower()).digest()
            for i in range(1, len(name)+1)
            for x in itertools.combinations(name, i)]

def encrypt(pkey, data):
    bio = M2Crypto.BIO.MemoryBuffer(pkey)
    rsa = M2Crypto.RSA.load_pub_key_bio(bio)
    c = ""
    bytes = 512/8-11
    for i in range(0,len(data),bytes):
        c += rsa.public_encrypt(data[i:i+bytes], M2Crypto.RSA.pkcs1_padding)
    return c
    

def decrypt(keys, data):  
    s = ""
    bytes = 512/8
    for i in range(0, len(data), bytes):
        s += keys.private_decrypt(data[i:i+bytes], M2Crypto.RSA.pkcs1_padding)
    return s    
    
def genRandomKey_old(x):
    return str(M2Crypto.BN.rand(256))[:x]

def __cipher_filter__(cipher, inf, outf):
    while 1:
        buf=inf.read()
        if not buf:
            break
        outf.write(cipher.update(buf))
    outf.write(cipher.final())
    return outf.getvalue()
	
def genRandomKey(x):
    return M2Crypto.Rand.rand_bytes(x/8)
