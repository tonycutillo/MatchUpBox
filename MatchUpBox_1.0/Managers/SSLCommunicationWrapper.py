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


import pickle
import socket
import ssl
import struct
import traceback
import time

# Yu
import cryptoV2 as crypto
#import crypto


import constants
import threading
import os
from base64 import b64encode, b64decode
from Messages import P2PMessage, MatMessage, Job

class SSLCommunicationWrapper:
    class session:
        def __init__(self,id,wrapSock,listnerThread):
            self.id=id#id = ip of target host
            self.wrapSock=wrapSock # ssl Socket
            self.listnerThread=listnerThread
    
    def __init__(self,dispatcher,isClient):
        self.sessions={}
        self.dispatcher=dispatcher
        f = open(constants.nid_filename, "r")
        self.nid = f.readline().strip()
        self.keys = crypto.loadKeyPair( self.nid + "_N_" )
        self.hostSSLport=443
        self.isClient=isClient
    
    def sslServer(self,arg):
        bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM )
        bindsocket.bind(('', self.hostSSLport))
        bindsocket.listen(5)
        prikeyPath='mypem'+os.sep+'pkey.pem'
        certPath='mypem'+os.sep+'cert.pem'
        while True:
            try:
                newsocket, fromaddr = bindsocket.accept()
                c = ssl.wrap_socket(newsocket, server_side=True, certfile=certPath,
                                    keyfile=prikeyPath, ssl_version=ssl.PROTOCOL_SSLv3)
                ssl_listerner = threading.Thread( target=self.sslListerner,
                                              name="Server_sslListerner_Thread",
                                              args=( c, fromaddr[0]) )
                ssl_listerner.daemon = True
                ssl_listerner.start()
                self.sessions[fromaddr[0]]=self.session(fromaddr[0],c,ssl_listerner)
            except:
                print 'sslServer: Connection Refused for Client '+str(fromaddr)
            
    def sslListerner(self,csock,id):
        while True:
            try:
                SizeStruct = struct.Struct( "!I" )          
                size_data = csock.recv(4)
                size, = struct.unpack("!I",size_data)
                
                result2 =''        
                start=0
                packetSize=5000
                dieCounter=0
                while len(result2)!=size:
                    if (len(result2)+packetSize) < size:
                        packet=csock.recv(packetSize)
                        
                        result2=result2+packet
                        start=start+len(packet)
                    else:
                        if dieCounter>=100:
                            print 'Unable to recieve all data on ssl channel'
                            break
                        packet=csock.recv(size-start)
                        
                        dieCounter+=1
                        result2=result2+packet
                        start=start+len(packet)
                        if len(result2)!=size:
                            time.sleep(1)
                
                try:            
                    msg = pickle.loads( result2 )
                except:
                    print 'SSL Thread Error: Cant load Pickle'
                    print traceback.print_exc()
                    continue
                traffic_type,item=msg
                if traffic_type=='UDP':
                    self.udpMsg_handler(item,id)
                else:
                    self.tcpMsg_handler(item,id)
            except socket.error, msg:
                print msg
                if self.isSession(id):
                    self.delSession(id)
                return
            except:
                print 'Error in SSL Server Listener- closing thread'
                return
    def udpMsg_handler(self,item,id):
        try:
            #print "UDP/SSL handler"
            dec_data = b64decode(crypto.decrypt( self.keys, item ))
            m = pickle.loads( dec_data )
            m.myIP=(id,str(self.hostSSLport),str(self.hostSSLport))
            m.isSSLPacket=True
            m.isClient=self.isClient
            job = Job( "R_P2P_" + m.type, m )
            #print m
            self.dispatcher.add( job )
        except:
            print 'Error in upd packet pickle load'
    def tcpMsg_handler(self,item,id):
        try:
            dec_data = b64decode(crypto.decrypt( self.keys, item ))
        except:
            print 'SSL TCP Handler: error in decrypt'
            print traceback.print_exc()
            return          
        try:            
            msg = pickle.loads( dec_data )
        except:
            print 'SSL TCP Handler: Cant load Pickle'
            print traceback.print_exc()
            return
        msg.type = "R" + msg.type[1:]
        
        msg.fromip = (id,str(self.hostSSLport),str(self.hostSSLport))
        msg.myIP=(id,str(self.hostSSLport),str(self.hostSSLport))
        msg.isSSLPacket=True
        self.dispatcher.add( msg )
   
    def sendOnSSL(self,item,trafic_type,sendtoip):
        # sends the packet on the ssl tunnel with wraping the msg in trafic type header
        # item: pickle/flat version of data to sent
        # trafic_type: UDP or TCP
        # sendto: ip to send
        # isClient: True if Client is sending a packet else false. it implies if client is sending a packet he can open a new session if needed but server cannot a open session so skip the send msg
        # The method checks the avalibility of session, if active sends the packet, else create a new session and send the packet
        if not(self.isSession(sendtoip)):#Create a new session for a request
            if self.isClient:
                status=self.createSession(sendtoip)
                if status==False:
                    return
            else:
                print 'I am server cannot open session for client'
                return    
        target_Session=self.getSession(sendtoip)
        sock=target_Session.wrapSock
        pkey = item.pkey
        item.pkey = None
        if trafic_type=='UDP':
            data_pickle = b64encode(pickle.dumps( item.data, pickle.HIGHEST_PROTOCOL))
            
            sslPacket=(trafic_type,crypto.encrypt(pkey, data_pickle))
            data = pickle.dumps( sslPacket, pickle.HIGHEST_PROTOCOL )
        else:
            
            data_pickle = b64encode(pickle.dumps( item, pickle.HIGHEST_PROTOCOL ))
            try:
                sslPacket = (trafic_type,crypto.encrypt( pkey, data_pickle ))
            except:
                print 'SendonSSL: Encryption error'
                return
            data=pickle.dumps( sslPacket, pickle.HIGHEST_PROTOCOL )
        try:
            SizeStruct = struct.Struct( "!I" )
            sock.sendall(struct.pack("!I",len(data)))
            start=0
            end=5000# Sending 5000 bytes
            size=len(data)
            while True:
                if end < size:
                    sock.sendall(data[start:end])
                    start=end
                    end=end+5000
                else:
                    sock.sendall(data[start:])
                    break
        except socket.error, msg:
                print msg
                if self.isSession(id):
                    self.delSession(id)
                return
        except:
            print "Error in SSL SEND"
            print traceback.print_exc()
            return
    def createSession(self,target):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM )
            c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE,
                                ssl_version=ssl.PROTOCOL_SSLv3)
            c.connect((target, self.hostSSLport))
            
            ssl_listerner = threading.Thread( target=self.sslListerner,
                                          name="sslListerner_Thread",
                                          args=( c, target) )
            ssl_listerner.daemon = True
            ssl_listerner.start()
            self.sessions[target]=self.session(id,c,ssl_listerner)
        except:
            print 'Cannot Create Session'
            print traceback.print_exc()
            return False
        
    def getSession(self,id):
        try:
            return self.sessions[id]
        except:
            return None

    def isSession(self,id):
        # Return True if Session is established else False
        if id in self.sessions.keys():
            return True
        return False
    def delSession(self,id):
        try:
            s=self.sessions[id]
            try:
                s.wrapSock.close()
            except:
                print 'error in closing socket'
                print traceback.print_exc()
#            if s.listnerThread.is_alive():
#                s.listnerThread.join(1)
            del self.sessions[id]
        except:
            print 'error in delete Session'
            print traceback.print_exc()
        
        
    def close(self):
        for id in self.sessions.keys():
            self.delSession(id)
        