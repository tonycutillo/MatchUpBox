import os
import M2Crypto
import cStringIO
import binascii

RSAKLEN = 512
RSAPEXP = 65537
ALG     = 'aes_256_cbc'
AESKLEN = 256


def genRsaKeys():
    keys = M2Crypto.RSA.gen_key(RSAKLEN, RSAPEXP, lambda: None)
    return keys

def storeRsaKeys(keys, filename):
    keys.save_key('mypem'+os.sep+filename+'_UKey.pem', None, lambda: None)
    keys.save_pub_key('mypem'+os.sep+filename+'_PKey.pem')
    return 0

def loadRsaUKey(filename):
    UKey = M2Crypto.RSA.load_key("mypem"+os.sep+filename+"_UKey.pem")
    return UKey

def loadRsaPKey(filename):
    PKey = M2Crypto.RSA.load_pub_key("mypem"+os.sep+filename+"_PKey.pem")
    return PKey
    
#def encryptRSA(PKey, ptxt):
#    c = ""
#    mbytes = RSAKLEN/8-11  # Yu: Why should minus 11 ???
#    for i in range(0,len(ptxt),mbytes):
#        c += PKey.public_encrypt(ptxt[i:i+mbytes], M2Crypto.RSA.pkcs1_padding)
#    #print "========RSA==len(ptxt) = " + str(len(ptxt))
#    #print "========RSA==len(ctxt) = " + str(len(c))
#    return c
def encryptRSA(PKey, ptxt):
    bio = M2Crypto.BIO.MemoryBuffer(PKey)
    rsa = M2Crypto.RSA.load_pub_key_bio(bio)
    c = ""
    mbytes = RSAKLEN/8-11  # Yu: Why should minus 11 ???
    for i in range(0,len(ptxt),mbytes):
        c += rsa.public_encrypt(ptxt[i:i+mbytes], M2Crypto.RSA.pkcs1_padding)
    #print "========RSA==len(ptxt) = " + str(len(ptxt))
    #print "========RSA==len(ctxt) = " + str(len(c))
    return c

def decryptRSA(UKeys, ctxt):  
    s = ""
    mbytes = RSAKLEN/8
    for i in range(0, len(ctxt), mbytes):
        s += UKeys.private_decrypt(ctxt[i:i+mbytes], M2Crypto.RSA.pkcs1_padding)
    return s

def genRN():
    password = M2Crypto.Rand.rand_bytes(AESKLEN/8)
    #print "=======AES==len(password) = " + str(len(password))
    return password
    
def encryptAES(password, ptxt):
    IV='\0'* (AESKLEN/8)
    k = M2Crypto.EVP.Cipher(ALG, password, IV, 1)
    pbuf=cStringIO.StringIO(ptxt)
    cbuf=cStringIO.StringIO()
    ctxt=cipher_filter(k, pbuf, cbuf)
    pbuf.close()
    cbuf.close()
    #print "=======AES==len(ptxt) = " + str(len(ptxt))
    #print "=======AES==len(ctxt) = " + str(len(ctxt))
    return ctxt

def decryptAES(password, ctxt):
    IV='\0'* (AESKLEN/8)
    j = M2Crypto.EVP.Cipher(ALG, password, IV, 0)
    pbuf=cStringIO.StringIO()
    cbuf=cStringIO.StringIO(ctxt)
    ptxt=cipher_filter(j, cbuf, pbuf)
    pbuf.close()
    cbuf.close()
    return ptxt

def cipher_filter(cipher, inf, outf):
    while 1:
        buf=inf.read()
        if not buf:
            break
        outf.write(cipher.update(buf))
    outf.write(cipher.final())
    return outf.getvalue()

def encrypt(pkey, ptxt):
    password = genRN()
    aesctxt = encryptAES(password,ptxt)
    rsactxt = encryptRSA(pkey,password)
    e = rsactxt + aesctxt
    return e.encode('base64')

def decrypt(ukey, ctxt):
    d = ctxt.decode('base64')
    rsaptxt = decryptRSA(ukey, d[0:RSAKLEN/8])  #Yu: how to get this from previous definition ??? RSA of a AES key
    aesptxt = decryptAES(rsaptxt, d[RSAKLEN/8:])
    return aesptxt


# Yu  22/04/2012
# copy from original crypto, used in Communication.py and SSLCommunicationWrapper.py  and Matryoshka.py
def loadKeyPrivate(name):
    keys = M2Crypto.RSA.load_key("mypem"+os.sep+name+"Keys.pem")
    return keys

def loadKeyPair(name):
    # return a M2Crypto.RSA.RSA object
    keys = M2Crypto.RSA.load_key('mypem/'+name+'Keys.pem', lambda: None)
    return keys

def decrypt_AES(ciphertext, skey, IV):
    j=M2Crypto.EVP.Cipher(alg='aes_256_cbc', key=skey, iv=IV, op=0)
    pbuf=cStringIO.StringIO()
    cbuf=cStringIO.StringIO(binascii.unhexlify(ciphertext))
    plaintext=cipher_filter(j, cbuf, pbuf)
    pbuf.close()
    cbuf.close()
    return plaintext

def sign(keys, data):
    dgst = M2Crypto.EVP.MessageDigest('sha1')
    dgst.update(data)
    return keys.sign(dgst.digest(), 'sha1')

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