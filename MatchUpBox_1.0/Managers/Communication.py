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

import logging 
import sys
import Managers.Manager as Manager
import cPickle as pickle
import socket
import struct
from Messages import P2PMessage, MatMessage, Job
import array
import threading

# Yu
import cryptoV2 as crypto
#import crypto

import os
import constants
import M2Crypto
import traceback
import thread
import time
from SSLCommunicationWrapper import SSLCommunicationWrapper

#import s2s.messages.P2PMessage

#@Ali UPNP Mapping
myPubaddr=()
ipMap={}
upnpFlag=False
sslFlag=False
file = open('conf'+os.sep+'ip.dat', 'rb')
sslFlag=False

if os.path.getsize(file.name)!= 0:
    line=file.readline()
    temp=line.split();
    myPubaddr=(temp[0],temp[1],temp[2],temp[3],int(temp[4]),False)
    sslFlag=True
else:
    try:
        import UPnPInterface
        upnp=UPnPInterface.UPnPInterface();
        upnpFlag=True
        pubIP=upnp.getPublicIP();
        priIP=upnp.getPriviteIP();
        tcpForPort=upnp.forwardPortTo(5000, 'TCP')
        udpForPort=upnp.forwardPortTo(4000, 'UDP')
        sslForPort=upnp.forwardPortTo(443, 'TCP')
        if int(sslForPort)!=443:
            upnp.removePortMaping(int(sslForPort), 'TCP')
            isSSL=0
        else:
            isSSL=1
        #Start SSL Server
        sslFlag=True
        myPubaddr=(pubIP,tcpForPort,udpForPort,priIP,isSSL,False)
    except Exception,e:
        print '''Please Enable UPnP on your router or contact your Administrator to Forward a X TCP and Y UDP port.
Then kindly, manually the configure the ip.dat in conf folder of MatchUpBox Installation Directory as following
Public_IP X Y Private_IP
e.g
82.55.x.x 5000 4000 192.168.1.x
            
            
Press Enter to run MatchUpBox with ssl...'''
#        raw_input()
        myPubaddr=('None','443','443','None',0,True)
file.close()
#######################################################################
# If u want to test the SSL Client, decomment the follwing two lines
#myPubaddr=('None','443','443','None',0,True)
#sslFlag=False
#######################################################################3
#@Ali
def tcp_recieveItem(csock, caddr,dispatcher,keys):
    try:
#        if caddr[0]=='83.201.26.105':
#            print 'start-1'
        SizeStruct = struct.Struct( "!I" )          
        size_data = csock.recv(4)
        size, = struct.unpack("!I",size_data)
        result2 =''        
        #@Ali
        start=0
        packetSize=5000
        dieCounter=0
        while len(result2)!=size:
            if (len(result2)+packetSize) < size:
                packet=csock.recv(packetSize) # recieve 100 KB
                
                result2=result2+packet
                start=start+len(packet)
            else:
                if dieCounter>=100:
                    print 'error: unable to recieve all bytes from '+str(caddr)
                    print 'error: bytes to send = '+str(size)
                    print 'error: bytes recieved = '+str(len(result2))
                    csock.close()
                    return
                packet=csock.recv(size-start)
                
                dieCounter+=1
                result2=result2+packet
                start=start+len(packet)
                if len(result2)!=size:
                    time.sleep(1)
        try:
            dec_data = crypto.decrypt( keys, result2 )
        except:
            print 'Communication Manager: error in decrypt'
            print traceback.print_exc()
            return
                     
        try:            
            msg = pickle.loads( dec_data )
        except:
            print 'TCP Thread Error: Cant load Pickle'
            print type(dec_data)
            print traceback.print_exc()
            return
                
        msg.type = "R" + msg.type[1:]
        try:
            msg.fromip = msg.myIP #@Ali
        except:
            msg.fromip = (caddr[0],'','')
        msg.isSSLPacket=False
        dispatcher.add( msg )

        csock.close()
    except socket.error, e:
        # A socket error
        print 'Recieve Socket Error'
        print socket.error
    except IOError, e:
        if e.errno == errno.EPIPE:
            print "broken pipe"
    except M2Crypto.RSA.RSAError as decerr:
        print 'hi i am in crypto error'
        print repr(decerr)
    except:
        print 'TCP Thread Error'
#            print dec_data
        print traceback.print_exc()
    csock.close()
#
def tcp_serverthread( dispatcher, ssock ):
    f = open(constants.nid_filename, "r")
    nid = f.readline().strip()
    
    keys = crypto.loadKeyPair( nid + "_N_" )
    # TONY: 
    #address = ( socket.gethostbyname_ex(socket.gethostname())[2][0], 5000 )
    address = ( "0.0.0.0", int(myPubaddr[1]) )#@Ali Random port
    ssock.bind( address ) 
    ssock.listen( 5 )
    logging.info( "TCP server started on {0}...".format( address ) )
    
    while True:
        try:
            csock, caddr = ssock.accept()

            tcp_handler_thread = threading.Thread( target=tcp_recieveItem,
                                      name="tcp_handler_thread for "+str(caddr),
                                      args=( csock, caddr,dispatcher,keys) )
            tcp_handler_thread.daemon = True
            tcp_handler_thread.start()
        except:
            print traceback.print_exc()
            
        
def udp_serverthread( dispatcher, udpSSock ):
    udpSSock.bind( ("0.0.0.0", int(myPubaddr[2]))  )#@Ali
    logging.info( "UDP server listening on port {0}...".format( myPubaddr[2] ) )#@Ali
    f = open(constants.nid_filename, 'r')
    nodeid = f.readline()
    f.close()
    keys = crypto.loadKeyPrivate(nodeid+"_N_")
    while True:
        try:
            data, addr = udpSSock.recvfrom( 30000 )
            try:
                dec_data = crypto.decrypt( keys, data ) #esko: p2p message decryption 
                
            except:
                print 'Communication Manager: error in p2p decrypt'
                print
                print traceback.print_exc() 
            
            m = pickle.loads( dec_data )
            
            m.isSSLPacket=False
            job = Job( "R_P2P_" + m.type, m )#@Ali addr contains the IP and the random port, so the sender attach the MYIP field with IP and its listening ports
            dispatcher.add( job )
            logging.info( "Received datagram from {0}".format( addr ) )
        except socket.error, e:
    # A socket error
            pass
        except IOError, e:
            if e.errno == errno.EPIPE:
                print "broken pipe"
    logging.info( "Closing UDP server" )
    udpSSock.close()


class CommunicationMng( Manager.Manager ):
    "Communication manager"
    
    def __init__( self, mName, main_mng ):
        super( CommunicationMng, self ).__init__( mName, main_mng )
        logging.info( "Communication Manager started..." )
        
        self.sslClientOnly=myPubaddr[5]
        self.isSSL=myPubaddr[4]
        if self.sslClientOnly==False:
            self.tcpSSockServ = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    
            self.tcp_server = threading.Thread( target=tcp_serverthread,
                                          name="tcp_serverthread",
                                          args=( self.main_mng, self.tcpSSockServ) )
            self.tcp_server.daemon = True
            self.tcp_server.start()
            
            self.udpSSockServ = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
            
            self.udpSSock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    		
            self.udp_server = threading.Thread( target=udp_serverthread,
                                          name="udp_serverthread",
                                          args=( self.main_mng, self.udpSSockServ ) )
            self.udp_server.daemon = True
            self.udp_server.start()
            self.i = 0
            
            if self.isSSL==1:#@Ali: start the ssl server in a seperate thread
                try:
                    testSocket=socket.socket()
                    self.sslComModule=SSLCommunicationWrapper(self.main_mng,False)
                    #Test if the port is already in use
                    testSocket.bind(('',self.sslComModule.hostSSLport))
                    testSocket.close()
                    self.ssl_server = threading.Thread( target=self.sslComModule.sslServer,
                                                  name="ssl_serverthread",
                                                  args=('startserver',) )
                    self.ssl_server.daemon = True
                    self.ssl_server.start()
                except:
                    #Cannot bind to SSL Port
                    print 'SSL Port Already in Use'
                    self.isSSL=0
                
        else:
            print 'Initializing the SSL Comunication Module'
            self.sslComModule=SSLCommunicationWrapper(self.main_mng,True)
        
        f = open('conf'+os.sep+'ipmap.dat', "r")
        for line in f.readlines():
            pubIP, tcp_port, udp_port, priIP= line.split()
            ipMap[(pubIP, tcp_port, udp_port)]=priIP

        f.close()
        
    def do_work( self, item ):
        if self.sslClientOnly==True:
            if item.type.startswith( "S_P2P" ):
                trafic_type='UDP'
                sendtoip=item.addr[0]
            else:
                trafic_type='TCP'
                sendtoip=item.to_ip[0]
            self.sslComModule.sendOnSSL(item, trafic_type, sendtoip) 
            
        elif item.type.startswith( "S_P2P" ):
            #@Ali
            if self.isSSL==1:
                if int(item.addr[2])==self.sslComModule.hostSSLport:
                    trafic_type='UDP'
                    sendtoip=item.addr[0]
                    self.sslComModule.sendOnSSL(item, trafic_type, sendtoip)
                    return
            send_to=( item.addr[0], int(item.addr[2]))
            if ipMap.has_key(item.addr) or item.addr[0]==myPubaddr[0]: #@Ali same network, chk ipmap for mapping or requeue the msg and wait for relay response
                if ipMap.has_key(item.addr):
                    send_to=( ipMap[item.addr], int(item.addr[2]))#@Ali send on local/private address
                else:#@Ali Requeue the item
                    self.main_mng.add(item)
                    return
            try:
                key = item.pkey
            except:
                print "unable to obtain public key for p2p traffic"    
            #print item.data
            #print item.addr[0]
            data = pickle.dumps( item.data, pickle.HIGHEST_PROTOCOL )
            #print key
            data = crypto.encrypt(key, data) #p2p message encryption
            try:
                self.udpSSock.sendto( data, send_to ) #@Ali Transmit the data on random port
            except:
                self.main_mng.add(item)
                print 'udp socket error'
                print traceback.print_exc()
                
            #
        else:
            #@Ali
            if self.isSSL==1:
                if int(item.to_ip[1])==self.sslComModule.hostSSLport:
                    trafic_type='TCP'
                    sendtoip=item.to_ip[0]
                    self.sslComModule.sendOnSSL(item, trafic_type, sendtoip)
                    return
            send_to=(item.to_ip[0],int(item.to_ip[1]))
            if ipMap.has_key(item.to_ip) or item.to_ip[0]==myPubaddr[0]: #@Ali same network, chk ipmap for mapping or requeue the msg and wait for relay response
                if ipMap.has_key(item.to_ip):
                    send_to=( ipMap[item.to_ip], int(item.to_ip[1]))#@Ali send on local/private address
                else:#@Ali Requeue the item
                    self.main_mng.add(item)
                    return
            #
            pkey = item.pkey
            item.pkey = None

            logging.info( "Communication manager is sending {0.type} to {1}".format( item, send_to ) )
            try:
                sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
                sock.connect( send_to )
                #item.myIP=(myPubaddr[0],myPubaddr[1],myPubaddr[2])

                SizeStruct = struct.Struct( "!I" )
                data = pickle.dumps( item, pickle.HIGHEST_PROTOCOL )
                en_data = crypto.encrypt( pkey, data )
                sock.sendall(struct.pack("!I",len(en_data)))
                start=0
                end=5000# Sending 1 MB
                size=len(en_data)
                while True:
                    if end < size:
                        sock.sendall(en_data[start:end])
                        start=end
                        end=end+5000
                    else:
                        sock.sendall(en_data[start:])
                        break
                sock.close()
            except socket.error as er:
                logging.info( "Socket error: {0}".format( er ) )
                print 'Socket Error'
                print item.type
                print send_to
                print item.to_ip
#                print ipMap
                print traceback.print_exc()
#                print 'Item added to the Queue for re-attempt'
#                item.pkey=pkey
#                self.main_mng.add(item)
                sock.close()
                return
            except:
#                item.pkey=pkey
#                self.main_mng.add(item)
                print traceback.print_exc()
#                print 'Item added to the Queue for re-attempt'
                sock.close()
                return

   
    def close( self ):
        logging.info( "Shutting down Communication Manager..." )
        #self.udpSSock.close()
        #self.udp_server.close()
        if self.sslClientOnly==True:
            try:
                self.sslComModule.close()
            except:
                pass
        else:
            # Remove Port Forwording Mappings
            if upnpFlag==True:
                try:
                    upnp.removePortMaping(int(myPubaddr[1]), 'TCP')
                    upnp.removePortMaping(int(myPubaddr[2]), 'UDP')
                    if self.isSSL:
                        upnp.removePortMaping(443, 'TCP')
                except:
                    pass                            
            try:
                self.udpSSockServ.close()
                self.udp_server.join(1)
            except:
                pass
            try:
                self.tcpSSockServ.close()
                self.tcp_server.join(1)
            except:
                pass
            #The following line store the ipMap to file, if useful for reducing the Replay request msgs, but if the users private ips are assigned through DHCP in this case it will not work. So decomment the lines if you are sure the network is has fixed Ips
#        f=open('conf'+os.sep+'ipmap.dat')
#        for map in ipMap.items():
#            k,v=map
#            s=str(k[0])+' '+str(k[1])+' '+str(k[2])+' '+str(v)+'\n'
#            f.write(s)
#        f.close()
        super( CommunicationMng, self ).close()
