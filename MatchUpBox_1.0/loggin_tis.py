#!/usr/bin/env python

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

from Managers.Matryoshka import FRE
from Managers.Matryoshka import FDE
from Managers.Matryoshka import DDE
import Managers.datamanager as datamanager
import Managers.crypto as crypto
import random, sys, functions, sqlite3, datetime
from base64 import b64encode, b64decode #@Ali
import os
import cPickle as pickle
import socket
import logging
import constants
import time
import struct
import traceback
databaseNamePrefix = 'dbData/db'
databaseNameExtension = '.db'

import threading
import webbrowser
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from os import curdir, sep
import cgi
answer=()
######
#This is the first library to interface the client whit the TIS
# and get in output the certificate for the client
def user_arguments():

    server = sbHTTPServer()
    server.start()                 # start the web server
        
    url='http://localhost:8080/login.html'
    web_ctrl = webbrowser.get()
    web_ctrl.open(url, 2, True)    # open the default web browser of the system
    while answer==():
	    pass;
    server.join()
    return answer
    
class loggin_tis:
    name=''
    txt=''
    K=''
    pwd=''
    tisHost=''
    tisPort=''
    proplist=[]
    CN=""
    
    BUFSIZE=100000
        
    def __init__(self, txt, K, pwd, tisHost, tisPort,avatar_name):
        logging.basicConfig(
            filemode = 'w',
            format   = "pid %(process)d -17s - %(asctime)s - %(levelname)s : %(message)s",
            level    = logging.DEBUG)
        
        self.name=''
        self.txt=txt
        self.K=K
        self.pwd=pwd
        self.tisHost=tisHost
        self.tisPort=int(tisPort)
        self.proplist=[]
        self.CN=""
        self.avatar_name=avatar_name
        
        #self.ipmap={"192.168.104.80":"193.55.113.90","192.168.104.81":"193.55.113.91","192.168.104.82":"193.55.113.92","192.168.104.83":"193.55.113.93"}

  
    def data_signed_crypted(self,data, keyPublic,keyPrivate,keyPrivate_node = None):
        logging.debug("Inside data_signed_crypted")  
        #####################################################################################
        #INPUT
        #-object unserialized
        #-public key
            #-private key
            #FUNCTION
            #-serializatoin of object in input
            #-signature of that object under private key
            #-serialization of object and signature
            #-cryption under public key
            #OUTPUT
            #E_publicKey((serialized)((serialized)data,signature_privateKey((serialized)data)))
            #if some problem appens it returns false
            #####################################################################################
        logging.debug("Try to dumps data")  
        try:
            picle_data = pickle.dumps(data,protocol=1)
        except:
            logging.error("Unable to serialize data")# check this!!!!!
            return False#check this!!!!!
        logging.debug("Try to dumps sig")          
        try:
            signature=crypto.sign(keyPrivate, picle_data)
        except:
            logging.error("Unable to sign data")# check this!!!!!
            return False#check this!!!!!
        logging.debug("Try to dumps data and sig")
        
        d_t=(picle_data, signature)
        
        if keyPrivate_node != None:
            logging.debug("Adding node signature")
            try:
                signature2=crypto.sign(keyPrivate_node, picle_data)
            except:
                logging.error("Unable to sign data")# check this!!!!!
                return False#check this!!!!!
            logging.debug("Try to dumps data and sig")
            d_t = (picle_data, signature, signature2)
        try:
            pkt=pickle.dumps( d_t, protocol=1)
        except:
            logging.error("Unable to serialize data")# check this!!!!!
            return False#check this!!!!!
        logging.debug("Try to crypt ")    
        try:
            output=crypto.encrypt(keyPublic,pkt)
        except:
            logging.error("Unable to crypto data")# check this!!!!!
            return False#check this!!!!!
        
        return output
        
    def send_data_signed_encrypted(self,cli,data, keyPublic,keyPrivate,keyPrivate_node=None):
        logging.debug("Inside send_data_signed_crypted")   
        try:
            tosend=self.data_signed_crypted(data, keyPublic,keyPrivate,keyPrivate_node)
            if(tosend==False):
                logging.error("Unable to create packet")# check this!!!!!
                cli.close()
                return False#check this!!!!!
        except:
            logging.error("Unable to create a packet")# check this!!!!!
            print traceback.print_exc()
            cli.close()
            return False#check this!!!!!
           
            #try to send tosend
        logging.debug("Try to send data")
        try:
            cli.sendall(tosend) 
        except socket.error, msg:
            logging.error("Unable to send "+tosend+": " + msg)
            print traceback.print_exc()
            cli.close()
            return False
           
        return True 
      
    def data_unsigned_decrypted(self,data, keyPublic,keyPrivate):
            #####################################################################################
            #INPUT
            #-object serialized and crypted under keYPublic
            #-public key
            #-private key
            #FUNCTION
            #-decryption under keyPublic
            #-signature verification
            #-unserialization data
            #-decryption under private key
            #OUTPUT
            #D_privateKey((serialized)((serialized)data,signature_privateKey((serialized)data)))
            #if some problem appens it returns false 
            #####################################################################################
        logging.debug("Inside data_unsigned_decrypted")
        logging.debug("Try to decrypt data")
        pkt_un=crypto.decrypt(keyPrivate, data) 
        logging.debug("Try to unserialize data and sig")
        #print pkt_un
        t  = pickle.loads(pkt_un)
        (data_p,signature) = t
        logging.debug("Try to verify sig")    
        if not (crypto.verify_sign(keyPublic,data_p, signature)):
            logging.error("Signature not verified")# check this!!!!!
            return False#check this!!!!
        logging.debug("Try to unserialize data")    
        data=pickle.loads(data_p)
        logging.debug("Return data")   
        return data
         
    def rcv_data_unsigned_decrypted(self,cli, keyPublic,keyPrivate ):
        logging.debug("Inside rcv_data_unsigned_decrypted")   
            #try to  receive
        logging.debug("Try to receive data")   
        
        #lalla = cli.recv(self.BUFSIZE)
        #data_received=lalla
        #lenlalla=len(lalla)

        #while len(lalla)==lenlalla and lenlalla != 192:
        #    lalla = cli.recv(self.BUFSIZE)
        #    data_received+= lalla
        try:
            #print cli.getpeername()
            size = cli.recv(4)
        
        except socket.error, e:
            print e
            sys.exit(1)
        size, = struct.unpack("!I",size)
        #print "size is: "+str(size)
        #size=192
        try:
            #data_t = cli.recv(self.BUFSIZE)
            data_t = cli.recv(size)
        except socket.error, e:
            print e
        data_received =data_t
        #TONY
        #print len(data_t)
        while len(data_received) < size:
            #data_t = cli.recv(self.BUFSIZE)
            data_t = cli.recv(1)
            data_received +=data_t
            #print len(data_received)
            
        logging.debug("Try decrypt and unserialize")
        data=self.data_unsigned_decrypted(data_received,keyPublic,keyPrivate)
        logging.debug("Return data")
        return data

    def getCertificate(self):

        logging.debug("Inside getCertificate")                        
            #try to create a socket
        logging.debug("Try to create socket")
        try:
            cli = socket.socket( socket.AF_INET,socket.SOCK_STREAM)  
        except:
            logging.error("Unable to open socket: ")
            cli.close()
            sys.exit(1)#check this!!!!!
        
        logging.debug("Try to connect at "+str(self.tisHost)+" port "+str(self.tisPort)) 
        try:
            cli.connect((self.tisHost, self.tisPort))
        except :
            logging.error("Unable to establish a connection")
            print traceback.print_exc()
            cli.close()
            sys.exit(1)#check this!!!!!
            #TIS+
        logging.debug("Try to retrive TIS public key")

        try:
            tis_public_key=crypto.loadPublicKey('TIS')
        except:
            logging.error("TIS public Key not found")
            cli.close()
            sys.exit(1)#check this!!!!!
            
        name=self.txt[0]+self.txt[1]
        logging.debug("Creation of keys u and n")
        #self.createKeys(name)    
        
        #create key pair   
        user=crypto.generateKeyPair()
        crypto.saveKeyPairs(user,name+"_U_")
        node=crypto.generateKeyPair()
        crypto.saveKeyPairs(node,name+"_N_")
            
            #U-
        logging.debug("Try to retrive U-")
        
        try:
            user_private_key=crypto.loadKeyPrivate(name+"_U_")
        except:
            logging.error("User private key not found")
            cli.close()
            sys.exit(1)#check this!!!!!
            
            #U+
        logging.debug("Try to retrive U+")
        try:
            user_public_key=crypto.loadPublicKey(name+"_U_")
        except:
            logging.error("User public key non found")
            cli.close()
            sys.exit(1)#check this!!!!!
            #N+ 
        logging.debug("Try to retrive N+")
        
        try:
            node_public_key=crypto.loadPublicKey(name+"_N_")
        except:
            logging.error("Node public key non found")
            cli.close()
            sys.exit(1)#check this!!!!!
        try:
            node_private_key=crypto.loadKeyPrivate(name+"_N_")
        except:
            logging.error("Node private key not found")
            cli.close()
            sys.exit(1)#check this!!!!!
  
        logging.debug("Try to retrive K")
        logging.debug("Try to send first pkt")
        try:
            temp=self.send_data_signed_encrypted(cli,(self.txt,user_public_key,node_public_key,self.pwd), tis_public_key,user_private_key ,node_private_key)
            if (temp==False):
                logging.error("Unable to send data")# check this!!!!!
                cli.close()
                sys.exit(1)
        except:
            logging.error("Unable to send data")# check this!!!!!
            cli.close()
            sys.exit(1)  
        
        logging.debug("Try to receive first packet")
        try:
            nonce=self.rcv_data_unsigned_decrypted(cli, tis_public_key,user_private_key )
            if not nonce:
                logging.error("Unable to receive data")
                cli.close()
                sys.exit(1)
        except:
            logging.error("Nonce not valid")
            cli.close()
            sys.exit(1)
        
        logging.debug("Try crypt nonce")   
        nonce_c=crypto.encrypt_AES(pickle.dumps(nonce, protocol=1),self.K,'00000000000000000000000000000000') 
        try:
            nonce_c=crypto.encrypt_AES(pickle.dumps(nonce, protocol=1),self.K,'00000000000000000000000000000000')
        except:
            logging.error("Unable to encrypt under K")
            cli.close()
            sys.exit()
        
        logging.debug("Try to send nonce")
        try:
            temp=self.send_data_signed_encrypted(cli,nonce_c, tis_public_key,user_private_key)
            if temp==False:
                logging.error("Unable to send data")# check this!!!!!
                cli.close()
                sys.exit(1)
        except:
            logging.error("Unable to send data")# check this!!!!!
            cli.close()
            sys.exit(1)   
            #  receiving credentiality
            #data_received = cli.recv(BUFSIZE)
        #self.BUFSIZE=10240
        logging.debug("Try to receive certificate")    
        cert=self.rcv_data_unsigned_decrypted(cli, tis_public_key, user_private_key)
        logging.debug("Saving certificate")
        (uidcert,nidcert, DHTLcert)=cert
        #self.BUFSIZE=1024
        #
        #logging.debug("Try to receive certificate")    
        #cert=self.rcv_data_unsigned_decrypted(cli, tis_public_key, user_private_key)
        #logging.debug("Saving certificate")
        
        logging.debug("Try to receive data of Core Node")
        #try:
        #Receiving core node data for the first friendship in one hope
        
        self.CN=self.rcv_data_unsigned_decrypted(cli, tis_public_key,user_private_key )
        pkeyBoot = self.CN[1][1] #esko: Receive nodeid,node public key from TIS 
        nidBoot = self.CN[1][0].encode('hex')
        tis_cert = self.CN[1][2]
        uidBoot = self.CN[0][0].encode('hex')
        bootAddress = self.CN[2]
        
        f=open('conf'+sep+'nodes.dat',"w")
        f.write(bootAddress + " 5000 4000 1 " + nidBoot)
        f.close()
        f=open('mypem/'+nidBoot+'_N_PKey.pem',"w")
        f.write(pkeyBoot)
        f.close() #esko end
        
        if not self.CN:
            logging.error("Unable to receive CN")
            cli.close()
            sys.exit(1)
        #I need cert of user and cert of node
        if self.CN.__len__()!=3:
           logging.error("Invalid data, i need two certificate of core node, user and node ")
           cli.close()
           sys.exit(1)
        if not functions.checkCertificate(self.CN[0],tis_public_key):
            logging.error("Invalid data, User certificate not valid ")
            cli.close()
            sys.exit(1)
        if not functions.checkCertificate(self.CN[1],tis_public_key):
            logging.error("Invalid data, Node certificate not valid ")
            cli.close()
            sys.exit(1)
        try:
            socket.inet_aton(self.CN[2])
            #TONY
            #print"cn[2] = "
            #print self.CN[2]
        except socket.error:
            logging.error("Invalid data, IP adress of core node not valid ")
            cli.close()
            sys.exit(1)
    
        f=open(constants.uid_filename,"w")
        f.write(uidcert[0].encode('hex'))
        f.close()
        
        f=open(constants.nid_filename,"w")
        f.write(nidcert[0].encode('hex'))
        f.close()
        
        #if not os.path.exists(constants.dhtfolder):
         #   os.makedirs(constants.dhtfolder)
        f2=open(constants.dhtfolder+os.sep+'DATA_'+uidcert[0].encode('hex'),"wb")
        
        lookUpData, cert_user, cert_node, friend_badge, online, ip_addr, trust = self.txt,uidcert,nidcert,None,False,'',1
        users = FRE(lookUpData, cert_user, cert_node, friend_badge, online, ip_addr, trust, "FRIENDSHIP_ESTABLISHED",[])
        
        certs_this_user = DHTLcert
        certs_this_user += [uidcert]
        cert_dhtlkeys = []
        cert_dhtlkeys += certs_this_user
        
        #saving the property list into a list into a structure ofa log calss
        names = ['name', 'surname', 'birth year', 'birth place', 'nationality']
        #[self.proplist.append((self.txt[i],DHTLcert[i])) for i in xrange(0,(names.__len__()))]
        #proplist=proplist[:3]+(male,)+proplist[3:]
        c=DHTLcert
        self.proplist=[]
        j=0
        for i in range(0,len(self.txt)):
            if i != 2:
                self.proplist.append([self.txt[i],c[j]])
                j+=1
            else:
                self.proplist.append([self.txt[i],None])
        
        #Adding empty property for ( mail, fixedtel, mobiletel, company, department, role, companymail, companytel, companymobiletel)
        for i in range(7,16):
            self.proplist.append(["",None])
            
        #adding the avatar
        f_avatar = open(self.avatar_name, 'rb' )
        binaryObject = f_avatar.read()
        f_avatar.close()
    
        self.proplist.append([b64encode(binaryObject),None])
        cta_box = {}
        d={}
        f2.write(str(b64encode(pickle.dumps(d, 2)))+"#")
        f2.write(str(b64encode(pickle.dumps(users, 2)))+"#")
        f2.write(str(b64encode(pickle.dumps(cert_dhtlkeys, 2)))+"#")
        f2.write(str(b64encode(pickle.dumps(cta_box, 2)))+"#")
#        pickle.dump(d, f2, 2) 
#        pickle.dump(users, f2, 2)
#        pickle.dump(cert_dhtlkeys, f2, 2)
#        pickle.dump(cta_box, f2, 2)
        f2.close()
        datamanager.createDatabase(uidcert[0].encode('hex'))
        datamanager.addPPIEntry(uidcert[0].encode('hex'), self.txt, self.avatar_name)
        db_filename = databaseNamePrefix +uidcert[0].encode('hex') + databaseNameExtension
        db_filename2 = databaseNamePrefix + uidcert[0].encode('hex') + databaseNameExtension
        conn = sqlite3.connect(db_filename)
        conn2 = sqlite3.connect(db_filename2)
        conn.isolation_level = None
        conn2.isolation_level = None
        c = conn.cursor()
        c2 = conn2.cursor()
        #c.execute(ppiInsertionQuery)
        #conn.commit()
        FDR = {}
        DDR = {}
        signedObject = [1]+[uidcert]+self.proplist + [crypto.sign(user_private_key, pickle.dumps([uidcert[0],uidcert]+self.proplist, pickle.HIGHEST_PROTOCOL))]
#        randomID = random.randint(0, 100000)
#        FDR[uidcert[0].encode('hex')] = [FDE(1, 0, 1, signedObject)]
#        DDR[randomID] = DDE(uidcert[0].encode('hex'), 0, 0)
#        c.execute("INSERT INTO BBB (id, data) VALUES (1, ?)", (str(b64encode(pickle.dumps(FDR, pickle.HIGHEST_PROTOCOL))),))
        c.execute('INSERT INTO FDR(UIDOWNER,Key_ID,DID,FCOUNT,Fr_ESDT) VALUES (?, ?,?, ?,?)', (uidcert[0].encode('hex'),0,1,1,b64encode(pickle.dumps(['PPI',1,0,signedObject]))))
#        c2.execute("INSERT INTO AAA (id, data) VALUES (1, ?)", (str(b64encode(pickle.dumps(DDR, pickle.HIGHEST_PROTOCOL))),))
    
        conn.commit()
        c.close()
        conn.close()
    
        conn2.commit()
        c2.close()
        conn2.close()

        crypto.saveKeyPairs(user, uidcert[0].encode('hex')+'_U_')
        crypto.saveKeyPairs(node, nidcert[0].encode('hex')+'_N_')
        
        f3=open(constants.bor_file,"wb")
        print self.CN[2]
        pickle.dump([self.CN[0],self.CN[1],self.CN[2],self.proplist],f3,pickle.HIGHEST_PROTOCOL)
        #pickle.dump([self.CN[0],self.CN[1],self.ipmap.get(self.CN[2]),self.proplist],f3,pickle.HIGHEST_PROTOCOL)
        f3.close()
        
        logging.debug("Removing old keys")
        os.remove('mypem'+os.sep+name+'_U_Keys.pem')
        os.remove('mypem'+os.sep+name+'_U_PKey.pem')
        os.remove('mypem'+os.sep+name+'_N_Keys.pem')
        os.remove('mypem'+os.sep+name+'_N_PKey.pem')

        cli.close()
        return cert
    
    def createBOR(self,mat):
        
        #return [propertylist,self.CN[0],self.CN[1],None,"Bootstrapping"]
        return [self.proplist,self.CN[0],self.CN[1],None,"Bootstrapping"]

class sbHTTPServer(threading.Thread):
    # the class that embeds the HTTP server
    
    def __init__(self):
        threading.Thread.__init__(self)
        self.handler = sbHTTPHandler
        self.server = HTTPServer(('localhost', 8080), self.handler)
        
    def run(self):
        self.server.serve_forever() # this thread is stuck here
        
    def join(self):
        self.server.shutdown()
        threading.Thread.join(self)

class sbHTTPHandler(BaseHTTPRequestHandler): 
    def do_GET(self):
        def writeResponse(response):
            # function to write the response coming from another manager (by means of a callback)
            # into the HTTP TCP socket and close it (by notifying to the lock that had stopped the HTTPHandler in another thread)
            resHTML = response.replace('<','&lt;').replace('>','&gt;').replace('\n','<br/>')
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(resHTML)

            # notify to make the do_GET method finish 
            # and then close the TCP connection (socket)
            self.cv.acquire()
            self.cv.notifyAll()
            self.cv.release()
        req = curdir + sep + "web" + self.path
        #print "============REQUEST IS: "+req

        self.send_response(200)
        f = None
        if self.path.find(".html")!=-1: # if it is a request for an html page
            f = open(req, "r")
            self.send_header('Content-type', 'text/html')
        elif self.path.endswith(".css"):
            f = open(req, "r")
            self.send_header('Content-type', 'text/css')
        elif self.path.endswith(".jpg"):
            f = open(req, "rb")
            self.send_header('Content-type', 'image/jpg')
        elif self.path.endswith(".png"):
            f = open(req, "rb")
            self.send_header('Content-type', 'text/png')
        elif self.path.endswith(".gif"):
            f = open(req, "rb")
            self.send_header('Content-type', 'text/gif')
        elif self.path.endswith(".ico"):
            #print "opening "+req
            f = open(req, "rb")
            self.send_header('Content-type', 'text/ico')
        elif self.path.endswith(".js"):
            f = open(req, "r")
            self.send_header('Content-type', 'application/x-javascript')
                  
                    
        if f!= None:
            self.end_headers()
            self.wfile.write(f.read())
            f.close()
        return	
    def do_POST(self):
        form = cgi.FieldStorage(
            fp=self.rfile, 
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
					 # Begin the response	
        firstName=form["firstName"].value
        lastName=form["lastName"].value
        gender=form["gender"].value
        birthDate=form["birthDate"].value
        birthPlace=form["birthPlace"].value
        country=form["country"].value
        avatar_location=constants.default_avatar
        tisout=form["tisout"].value
        K=functions.retrive_K(tisout)
        password=form["password"].value
        
        tisadd=constants.tis_ip    
        tisport=constants.tis_port

        logging.info("loggin_tis - returning values")
        global answer
        answer=firstName,lastName,gender,birthDate,birthPlace,country,avatar_location,K,password,tisadd,tisport
        return
