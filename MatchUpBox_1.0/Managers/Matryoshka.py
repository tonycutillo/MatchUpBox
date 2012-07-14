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
import random
import sys
from Messages import MatMessage, Job, relayMessage
import binascii

# Yu
import cryptoV2 as crypto
#import crypto

import Managers.Manager as Manager
import array
import struct
import threading
import hashlib
import cPickle as pickle
import time
import os
import shutil
import socket
import functions
import cStringIO
import sqlite3
import constants
#andrea
import traceback
import thread
from base64 import b64encode, b64decode #@Ali


debug = True
interval_store_dicts = 20
delegate_threshold = 0.1
AESKLEN=256
IV='\0'* (AESKLEN/8)
from Managers.Communication import myPubaddr
# TONY
#def timer(disp, C, Nid, status):
#    data = (C, Nid, status)
#    disp.add(Job("R_MAT_MTO", data))
#    logging.info("Timeout: {0}".format(status))


class MRC: # Matryoshka Rounting Contact
    def __init__(self, Nid_inh, node_list, pcr):
        self.Nid_inh = Nid_inh
        self.node_list = node_list
        self.pcr = pcr
    def __repr__(self):
        return "[Nid_inh: {0.Nid_inh} - node_list: {0.node_list} - pcr: {0.pcr}]".format(self)
       
class DRE:
    def __init__(self, Nid, rand_num):
        self.Nid = Nid
        self.rand_num = rand_num
      
class DDE:
    def __init__(self, sf, kid, count):
        self.sf = sf
        self.kid = kid
        self.count = count
        
class FDE:
    def __init__(self, fkid, fid, fcount, es_dtok):
        self.fcount = fcount
        self.fkid = fkid
        self.fid = fid
        self.es_dtok = es_dtok
    
class FRE: # Friend Entry
    def __init__(self, name, cert_user, cert_node, friend_badge, online, ip_addr, trust, status, listofkeys):
        self.name = name
        self.cert_user = cert_user
        self.cert_node = cert_node
        self.friend_badge = friend_badge
        self.online = online
        self.ip_addr = ip_addr
        self.trust = trust
        self.status = status
        self.listofkeys = listofkeys #@Ali
        
    def __repr__(self):
        cert_user_tmp = list(self.cert_user)
        cert_node_tmp = list(self.cert_node)
        cert_user_tmp[0] = binascii.hexlify(cert_user_tmp[0])
        cert_user_tmp[2] = binascii.hexlify(cert_user_tmp[2])
        cert_node_tmp[0] = binascii.hexlify(cert_node_tmp[0])
        cert_node_tmp[2] = binascii.hexlify(cert_node_tmp[2])
        return ("[{0.name}, "
                "({1[0]:.3}..., {1[1]:.3}..., {1[2]:.3}...), "
                "({2[0]},  {2[1]:.3}..., {2[2]:.3}...), "
                "{0.friend_badge}, {0.online}, {0.ip_addr}, "
                "{0.trust}]".format(self, cert_user_tmp, cert_node_tmp))

class FEP: # Friend Entrypoint
    def __init__(self, cert_node, ip_addr, reg_time, exp_time,isSSL=None):
        self.cert_node = cert_node
        self.ip_addr = ip_addr
        self.reg_time = reg_time
        self.exp_time = exp_time
        self.isSSL=isSSL

class MatryoshkaMng(Manager.Manager):
    "Matryoshka manager"
    
    def __init__(self, mName, main_mng, usr_mng):
        super(MatryoshkaMng, self).__init__(mName, main_mng)
        logging.info("Matryoshka Manager started...")  
        
        logger = logging.getLogger("Matryoshka")        
        fmt = logging.Formatter("%(threadName)-17s - %(asctime)s: - %(message)s")
        handler=logging.FileHandler("log"+os.sep+"Matryoshka.log","w")#)
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        self.logger=logger
        #@Ali
        self.badges={} #Keys for access control of user profile
        self.FAC={} #Friend Access control list
        self.myIP=(myPubaddr[0],myPubaddr[1],myPubaddr[2])
        self.isSSL=myPubaddr[4]
        self.sslClientOnly=myPubaddr[5]
        #
        self.MRM = {} # Matryoshka Routing Map
        self.FRT = {} # Friend Table
        self.FET = {} # Friend Entrypoint Table
        self.NUid = {}
        self.DDR = {}
        self.FDR = {}
        self.DRM = {}
        self.DRM_chk={}#@Ali Keep track of multiple DFC for a single request
        self.RDC={}#@Ali Recieved Data Counter
        self.myFRE = None
        self.keys = None
        self.max_ttl = 2
        self.span = 1
        self.ep_alpha = 1
        self.ExpireTime = 2 # days
        self.dhtlkeys = None
        self.cert_dhtlkeys = None
        self.ack_time = 5
        self.res_time = 10
        self.max_mirror = 1
        self.usr_mng = usr_mng
        self.cta_box = {} #CTA mail box
        self.flag = {}
        self._load_objects()
        self.save_interval = 60*10
        self.save_timer=threading.Timer(self.save_interval, self._save_objects)
        self.save_timer.setName('MAT_save_Timer')
        self.save_timer.start()
        self.lock_data = threading.Lock()
        self.running = True
        #self.create_data()
        #sys.exit()
        self.iAmEntryPointOf = {}
		
		
        #@Ali Timmer to update the DRM open slots or clean the DRM
        self.DRM_Update_Interval=5*60
        self.updateDRM_Timmer=threading.Timer(self.DRM_Update_Interval, self.updateDRM)
        self.updateDRM_Timmer.setName('DRM_Update_Timmer')
        self.updateDRM_Timmer.start()
        
        self.big_brother = True
        if self.big_brother:
            self.big_brother_ip = "192.168.104.90"
            self.big_brother_port = 4000
            self.big_brother_interval = 10
            self.b_sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
            self.big_brother_timer=threading.Timer(self.big_brother_interval, self.send_big_brother)
            self.big_brother_timer.setName('big_brother_Timer')
            #self.big_brother_timer.start()
            #self.udpSSock.sendto( pickle.dumps( item.data, 2 ), ( item.addr[0], int(port) ) )
            
    def updateDRM(self):
        TTL=60*10#10 mins
        current_timestamp=int(round(time.time()))
        for key,reqID_tup in self.DRM_chk.items():
            leaseTime=current_timestamp-reqID_tup[2]
            if leaseTime>=TTL:
                self.lock_data.acquire()
                try:
                    del self.DRM_chk[key]
                except:
                    self.logger.info( 'DRM Timmer: Error deleting DRM_chk')
                    pass
                try:
                    self.logger.info( 'updateDRM_Timmer: Deleting Unresponsive entries form DRM ')
                    index=0
                    flag=False
                    for entry in self.DRM[key[0]]:
                        if entry.rand_num==key[1]:
                            flag=True
                            break
                        index+=1
                    if flag==True:
                        del self.DRM[key[0]][index]
                except:
                    self.logger.info( 'DRM Timmer: Error deleting DRM')
                    pass
                self.lock_data.release()
        self.updateDRM_Timmer=threading.Timer(self.DRM_Update_Interval, self.updateDRM)
        self.updateDRM_Timmer.setName('DRM_Update_Timmer')
        self.updateDRM_Timmer.start()
        
            
    def send_big_brother(self):
        if not self.big_brother:
            return
        my_uid = str(self.myFRE.cert_user[0].encode('hex'))
        my_nid = str(self.myFRE.cert_node[0].encode('hex'))
        my_name = str(self.myFRE.name[0])+"_"+str(self.myFRE.name[1])[:1]
        data = [my_uid, my_nid,my_name,True]
        #self.b_sock.sendto( pickle.dumps(data,pickle.HIGHEST_PROTOCOL), ( self.big_brother_ip, int(self.big_brother_port)) )
        list = []
        if not self.running:
            data = [my_uid, my_nid,my_name,False]
            #self.b_sock.sendto( pickle.dumps(data,pickle.HIGHEST_PROTOCOL), ( self.big_brother_ip, int(self.big_brother_port)) )
            list = []
            data .append(list)
            self.b_sock.sendto( pickle.dumps(data,pickle.HIGHEST_PROTOCOL), ( self.big_brother_ip, int(self.big_brother_port)) )
            return
        for C in self.MRM:
            #print "aaaa"
            inh =  self.MRM[C].Nid_inh
            #print inh
            if inh == None:
                continue

            inh = str(inh.encode('hex'))
            C_str = str(C.encode('hex'))
            if (C in self.FRT and self.FRT[C].online) or C == self.myFRE.cert_user[0] :
                pass
            else:
                continue
            
            node = None
            for el in self.MRM[C].node_list:
                if el[1] == "ESTABLISHED":
                    node = str(el[0].encode('hex'))
                    list.append([C_str , inh, node])
            #print node
            
            
        data .append(list)
            #print data
            
        self.b_sock.sendto( pickle.dumps(data,pickle.HIGHEST_PROTOCOL), ( self.big_brother_ip, int(self.big_brother_port)) )
        if self.running == False:
            self.big_brother_timer.cancel()
            
        else:
            self.big_brother_timer=threading.Timer(self.big_brother_interval, self.send_big_brother)
            self.big_brother_timer.setName('big_brother_Timer')
            self.big_brother_timer.start()
            
    def _load_objects(self):
        '''
            load dictionary objects from databases
            load: DDR, FDR
            call load_objects on user manager, datamanager
            fill the map structure DDR, FDR
            @return: Nothing
        '''
        return
#        objectNames = ['AAA', 'BBB']
#        try:
#            for name in objectNames:
#                if self.usr_mng.dbm.load_objects(name) is not None:
#                    setattr(self, name, self.usr_mng.dbm.load_objects(name))
#                    if name=='BBB':
#                        for item in self.BBB.items():
#                            uid,fre_obj=item
#                            fcount,fkid,fid,proplist=fre_obj[0].fcount,fre_obj[0].fkid,fre_obj[0].fid,fre_obj[0].es_dtok
#                            proplist=[1]+proplist
#                            if functions.getUid()==uid:    
#                                fcount=1
#                            else:
#                                fcount=0
#                            if proplist[2][0]=='One' or proplist[2][0]=='Two' or proplist[2][0]=='Three' or proplist[2][0]=='Four':
#                                proplist[17][0]=b64encode(proplist[17][0])
#                            self.usr_mng.dbm.addupdateFDR(uid,1,fcount,0,b64encode(pickle.dumps(['PPI',1,0,proplist])))
#                else:
#                    print name, 'table is empty.'
#        except:
#            print traceback.print_exc()
#            pass
#        return
    
    def _save_objects(self):
        ''' 
            save dictionary objects to databases
            save 
                DDR and FDR on database calling save_objects on usermanager, datamanager
                FRT, myFRE and certdhlkeys on file userdata/DATA_userid(in hex) using pickle.dump
            
            @return: Nothing
        '''
        self.lock_data.acquire()
        #save FRT table to the file
        f = open("user_data"+os.sep+"DATA_" + binascii.hexlify(self.myFRE.cert_user[0]) , "wb")
        
        f.write(str(b64encode(pickle.dumps(self.FRT, 2)))+"#")
        f.write(str(b64encode(pickle.dumps(self.myFRE, 2)))+"#")
        f.write(str(b64encode(pickle.dumps(self.cert_dhtlkeys, 2)))+"#")
        f.write(str(b64encode(pickle.dumps(self.cta_box, 2)))+"#")
        f.close()
        self.lock_data.release()
        if self.running == False:
            self.save_timer.cancel()
        else:
            self.save_timer=threading.Timer(self.save_interval, self._save_objects)
            self.save_timer.setName('MAT_save_Timer')
            self.save_timer.start()
        return
    
    #===========================================================================
    # def create_data(self):
    #    users = []
    #    for i, ip in zip(range(0, 6), "156234"):
    #        letter = chr(ord('A')+i)
    #        name = (letter+"_Name",letter+"_Surname", ip+"/10/2010")
    #        crypto.createKeyPair(name[0]+"_U_")
    #        crypto.createKeyPair(name[0]+"_N_")         
    #        
    #        uid = crypto.createUId(name)
    #        nid = crypto.createNId(name)
    #        
    #        pubKey = crypto.loadPublicKey(name[0]+"_U_")
    #        signature = crypto.tis_sign(uid+pubKey)
    #        cert_user = (uid, pubKey, signature)
    #        
    #        pubKey = crypto.loadPublicKey(name[0]+"_N_")
    #        signature = crypto.tis_sign(nid+pubKey)
    #        cert_node = (nid, pubKey, signature)
    #        
    #        friend_badge = None
    #        online = False
    #        ip_addr = socket.gethostbyname_ex(socket.gethostname())[2][0]
    #        trust = random.randint(0, 50) 
    #        users += [FRE(name, cert_user, cert_node, friend_badge, online, ip_addr, trust)]
    #        
    #        filename = "s2s"+ip+".conf"
    #        f = open(filename,"w")
    #        f.write(nid.encode('hex'))
    #        
    #        if ip != "1":
    #            f.write('\n')
    #            f.write("127.0.0.1 4001")
    #        f.write('\n')
    #        f.close()            
    #        
    #        
    #        
    #    A_FRT = {users[1].cert_user[0]:users[1]}
    #    B_FRT = {users[0].cert_user[0]:users[0], users[2].cert_user[0]:users[2], users[5].cert_user[0]:users[5]}
    #    C_FRT = {users[1].cert_user[0]:users[1], users[3].cert_user[0]:users[3], users[4].cert_user[0]:users[4]}
    #    D_FRT = {users[2].cert_user[0]:users[2]}
    #    E_FRT = {users[2].cert_user[0]:users[2]}
    #    F_FRT = {users[1].cert_user[0]:users[1]}
    #    letters = "ABCDEF"
    #    dicts = [A_FRT, B_FRT, C_FRT, D_FRT, E_FRT, F_FRT]
    #    for d, l, u in zip(dicts, letters, users):
    #        f = open("user_data/"+l+"_DATA", "wb")
    #        pickle.dump(d, f, 2)
    #        pickle.dump(u, f, 2)
    #        f.close()
    #===========================================================================
    def printFRT(self):
        '''
            print FRT and NUid
                each element of FRT is printed as: FRT: uid (hex) \n \t string of FRT[uid]
                each element of NUid is printed as: NUid: uid (hex) \n\t nid (hex)
            @return: Nothing
        '''
        for elemento in self.FRT:
            #print "FRT: "+ str(binascii.hexlify(elemento))+"\n"
            print "name: "+ str(self.FRT[elemento].name)
            print "\t online:"+str(self.FRT[elemento].online)
            print "\t status:"+str(self.FRT[elemento].status)+"\n"
        #for elemento in self.NUid:
        #    print "NUid: "+ str(binascii.hexlify(elemento))+"\n"
        #    print "\t"+str(binascii.hexlify(self.NUid[elemento]))
        

#TONY
    def remFriendbyName(self):
        todelname=raw_input("Insert the name of the friend you want to remove > ")
        todelUid = None
        print "looking for" + str(todelname)
        for elem in self.FRT:
            if str(self.FRT[elem].name[0]) == str(todelname):
                todelUid=elem
        if todelUid != None:
            print "removing " + todelname
            self.removeFriend(todelUid)
#TONY
    def setFRest(self):
        toESTname=raw_input("Insert the name of the friend you want to set FRIENDSHIP_ESTABLISHED with > ")
        toESTUid = None
        for elem in self.FRT:
            if str(self.FRT[elem].name[0]) == str(toESTname):
                toESTUid=elem
        if toESTUid != None:
            print "setting Friendship established with " + toESTname
            self.FRT[toESTUid].status="FRIENDSHIP_ESTABLISHED"
    
    def printMRM(self):
        '''
            print the MRM in readable format, if I've the name put the name, else the uid, else the nid
                each elemnt print: Core (name or uid ) - inner (name or uid or nid) - node_list (name or uid or nid)
                
                the core is the matryoshka core
                the inner id the innerHop
                node_list is the list of outer hop
                
                if I have the name (mean is one of my friend, print the name
                else if I have only the uid print the uid
                else print the nid
                
            @return: Nothing
        '''
        for core in self.MRM:
            c_name = "uid: "+str(core.encode('hex'))
            if core in self.FRT:
                c_name = "name: "+str(self.FRT[core].name[0])
            
            inh_nid = self.MRM[core].Nid_inh
            if inh_nid != None:
                inh_name = "nid: "+str(inh_nid.encode('hex'))
                if inh_nid in self.NUid:
                    inh_uid = self.NUid[inh_nid]
                    inh_name = "uid: "+str(inh_uid.encode('hex'))
                    if inh_uid in self.FRT:
                        inh_name = "name: "+str(self.FRT[inh_uid].name[0])
            else:
                inh_name = "NONE"
            
            n_h_l = ""
            for n_h_nid in self.MRM[core].node_list:
                n_h_name = "nid: "+str(n_h_nid[0].encode('hex'))+"\t"
                if n_h_nid[0] in self.NUid:
                    n_h_uid = self.NUid[n_h_nid[0]]
                    n_h_name = "uid: "+str(n_h_uid.encode('hex'))+"\t"
                    if n_h_uid in self.FRT:
                        n_h_name = "name: "+str(self.FRT[n_h_uid].name[0])+"\t"
                n_h_l +=str(n_h_name)+"status: "+str(n_h_nid[1])
                
            print "Core:"+c_name+" - inner:"+inh_name+" - node_list"+n_h_l

    def load_data(self):
        '''
            load data for Matryoshka
            uid using function retrieveUid()
            FRT, myFRE and certdhlkeys from file userdata/DATA_userid(in hex) using pickle.load (the same saved by save_objects)
            keys (user public and private keys) from file mypem/uid(hex)_U_
            NUid filled using the FRT table
            
            @return: Nothing
            
        '''
        if self.myFRE!=None:
            return
        uid = functions.retrieveUid()
        
        f = open("user_data"+os.sep+"DATA_" + uid , "r")
     
        data=f.read()
        token=data.split('#')
        self.lock_data.acquire()
        self.FRT=pickle.loads(b64decode(token[0]))
        #Setting all friends offline
        for x in self.FRT.values():
            x.online=False
        self.myFRE = pickle.loads(b64decode(token[1]))
        #self.myFRE.ip_addr = addr
        self.myFRE.ip_addr =self.myIP
        #print self.myFRE.ip_addr
        self.cert_dhtlkeys = pickle.loads(b64decode(token[2]))
        if len(token[3])!=0:
            self.cta_box = pickle.loads(b64decode(token[3]))
        else:
            self.cta_box={}
        f.close()
        self.keys = crypto.loadKeyPair(uid+"_U_")

        for key, value in self.FRT.items():
            self.NUid[value.cert_node[0]]= key
        self.lock_data.release()
        self.usr_mng.setparameterforusr_mng(self.myFRE,self.cert_dhtlkeys,self.keys)
    def receivedMLI(self):
        '''
            Matryoshka Login
            called when receive MAT_MLI
            load data using load_data function 
            check the number of friend
                if I have at least one friend (so send a Friend IP request to P2P
                else load a bootstrap request from bor_file and call the function sendBOR
                
            the bor_file is created by logging_tis with the data received from the tis
            
            @return: Nothing
        '''
        self.load_data()
        
        if(len(self.FRT)<1):
            #I don't have friends
            #load bor data from the bor_file created by logging tis
            f=open(constants.bor_file,"rb")
            bor=pickle.load(f)
            f.close();
            self.sendBOR(bor[0], bor[1], (bor[2],'5000','4000'), bor[3])#@Ali Modify TIS code to send ports as well. 
        else:
            #I have friends, so start looking who is online among my friends
            self.sendFIP()
        if self.big_brother:
            self.big_brother_timer.start()
            
    def receivedDFC(self, item):
        '''
            Received Data Fetch confirmation
            received as response to a DFR (data fetch request)
            receive the response
                check if the core is in my DRM
                if I'm the requester
                    update my the database
                    PPI using addUpdatePPI function on usermanager, datamanager
                    PPT addUpdatePost function on usermanager, datamanager
                else
                    forward the request to the interested node (looking at the Matryoshka Routing Map )
            delete the entry in my DRM
            
            @param  item: ( a MatMessage defined in Messages)
                     item.data = [C, fdeL, isPPI]
                         C = the core
                         fdel = list of FDE
                         isPPI = boolean if TRUE PPI data, else PST
        '''
        C, fdeL, isPPI,requestID_tup = item.data
        requestID,totalTok=requestID_tup
        Nid = self.myFRE.cert_node[0]
        #i'm serving for a find request at user manager 
        
        if C not in self.DRM:
            self.logger.error("receivedDFR: I didnt requested the data")
            return
     
        #for every requester of data about C    
        for x in self.DRM[C]:
            # if i am the requester of C's data
            if x.Nid == Nid:
                if isPPI=='find': # handle the find request for user manager
#                    print 'DFC for find'
#                    print 'DFC: recieved :'+str(len(fdeL))
                    listdata=pickle.loads(b64decode(fdeL))
#                    print 'listdata len = '+str(len(listdata))
                    for fde in listdata:
                        try:
                            uid,did,fcount,kid,content = fde[0]
                        except:
                            print 'none suppoerted parameter for DFC'
                            return
                        if kid==0:
                            data=pickle.loads(b64decode(content))
                            Type,fcount_chk,kid_chk,esdt_pickle=data
                            if Type=='PPI':
                                print 'forwarding to addsearchResults'
                                self.usr_mng.addSearchResult([C,fcount,esdt_pickle])
                            else:
                                continue
                        else:
                            continue
                
                elif C in self.FRT and self.FRT[C].status == "FRIENDSHIP_ESTABLISHED":
                    fdel_obj=pickle.loads(b64decode(fdeL))                 
                        #@Ali
                    
                    for fde in fdel_obj:
                        uid,did,fcount,kid,content = fde
#                        print kid
                        if kid==0:
                            data=pickle.loads(b64decode(content))
                        else:
                            key=self.usr_mng.dbm.getkeyDKR(kid)
                            try:
                                data=pickle.loads(b64decode(crypto.decrypt_AES(str(content), str(key), IV)))
                            except:
                                continue
                        type,fcount_chk,kid_chk,esdt=data
                        if fcount!=fcount_chk and kid!=kid_chk:
						    #FIXME
                            self.logger.info( 'Recieved Data is tempered, Rejected...')
                            continue
                        
                        if type == 'PPI':
                            if len(esdt)==19:
                                if did!=esdt[0]:
                                    print 'Recieved Data is tempered, Rejected...'
                                    print 'did='+str(did)+' esdt=[0] '+str(esdt[0])
                                    continue
                                proplist=esdt[2:]
                                id=binascii.hexlify(esdt[1][0])
                            elif len(esdt)==3:
                                uidcertsender,proplist_enc,signatures=esdt
                                proplist_all=pickle.loads(b64decode(proplist_enc))
                                if did!=proplist_all[0]:
                                    print 'Recieved Data is tempered, Rejected...'
                                    print 'did='+str(did)+' esdt=[0][4][3][0] '+str(proplist_all[0])
                                    continue
                                proplist=proplist_all[1:]
                                id=binascii.hexlify(uidcertsender[0])
                            else:
                                print 'DFC-PPI: I am last condition esdt[0][4][3][0]'
                                if did!=esdt[0][4][3][0]:
                                    print 'Recieved Data is tempered, Rejected...'
                                    print 'did='+str(did)+' esdt=[0][4][3][0] '+str(esdt[0][4][3][0])
                                    continue
                                proplist=esdt[0][4][3][2:]
                                id=binascii.hexlify(esdt[0][4][3][1][0])
                            print "Updating Personal Private Information of "+str(self.FRT[binascii.unhexlify(uid)].name)    
                            chkVersion=self.usr_mng.dbm.addRDR(did,uid,type,fcount,kid)
                            if chkVersion:
                                self.usr_mng.dbm.addUpdatePPI(id,proplist[0][0],proplist[1][0] ,proplist[2][0] ,proplist[3][0] ,proplist[4][0] ,proplist[5][0] ,proplist[6][0] ,proplist[7][0] ,proplist[8][0] ,proplist[9][0] ,proplist[10][0] ,proplist[11][0] ,proplist[12][0] ,proplist[13][0] ,proplist[14][0] ,proplist[15][0])
                        if type == 'PST':
                            if did!=esdt[0]:
                                print 'PST did does not correspond to ESDT'
                                continue
                            print "Updating posts of "+str(self.FRT[binascii.unhexlify(uid)].name)
                            chkVersion=self.usr_mng.dbm.addRDR(esdt[0],uid,type,fcount,kid)
                            if chkVersion:
                                self.usr_mng.dbm.addUpdatePost(esdt[0],esdt[1],esdt[2],esdt[3],esdt[4],esdt[5],esdt[6])
                        elif type == 'PCT':
                            if did!=esdt[0]:
                                print 'PCT did does not correspond to ESDT'
                                continue
                            print "Updating pictures of "+str(self.FRT[binascii.unhexlify(uid)].name)
                                #print fde.es_dtok[2][8]
    #                            picData = buffer( fde.es_dtok[2][8] )
                            chkVersion=self.usr_mng.dbm.addRDR(esdt[0],uid,type,fcount,kid)
                            if chkVersion:
                                self.usr_mng.dbm.addUpdatePicture(esdt[1],esdt[2],esdt[3],esdt[4],esdt[5],esdt[6],esdt[7],esdt[8],esdt[9],esdt[0])
                        elif type == 'ALB':
                            if did!=esdt[0]:
                                print 'ALB did does not correspond to ESDT'
                                continue
                            print "Updating album info of "+str(self.FRT[binascii.unhexlify(uid)].name)
                            chkVersion=self.usr_mng.dbm.addRDR(esdt[0],uid,type,fcount,kid)
                            if chkVersion:
                                self.usr_mng.dbm.addUpdateAlbum(esdt[1],esdt[2],esdt[3],esdt[0])                    

            #if i'm not the requester of C's data
            else:
                if self.MRM[C].node_list == []:
                    target_ip = x.Nid[0]
                    pkey = x.Nid[1]
                else:
                    key = self.NUid[x.Nid]
                    target_ip = self.FRT[key].ip_addr
                    pkey =  self.FRT[key].cert_node[1]
                    
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_DFC", (C, fdeL, isPPI,requestID_tup), target_ip,
                                            pkey))
#                self.logger.info("Matryoshka has created: {0} "
#                             "------ {1} -> {2}".format("S_MAT_DFC", self.myFRE.name[0], self.FRT[key].name[0]))
        #@Ali
        if (C,requestID) in self.DRM_chk.keys():
            if self.DRM_chk[(C,requestID)][0:2]==[-1,-1]:
                self.DRM_chk[(C,requestID)][0:2]=[totalTok,1]
            else:
                self.DRM_chk[(C,requestID)][1]+=1
            total_tokens,recieved_tokens=self.DRM_chk[(C,requestID)][0:2]
        else:
            self.logger.info( 'total_tokens=recieved_tokens=-1 ---- Condition should never come')
            total_tokens=recieved_tokens=-100
        if total_tokens==recieved_tokens:
            self.lock_data.acquire()
            try:
                del self.DRM_chk[(C,requestID)]
            except:
                self.logger.info( 'DFC: Error in DRM_chk delete')
                pass
            try:
                index=0
                flag=False
                for entry in self.DRM[C]:
                    if entry.rand_num==requestID:
                        flag=True
                        break
                    index+=1
                if flag==True:
                    del self.DRM[C][index]
            except:
                self.logger.info( 'DFC: Error in DRM delete')
                pass
            self.lock_data.release()
        #
    def receivedDFR(self, item):
        '''
            Received Data Fetch Request
            @param:    item ( a MatMessage defined in Messages)
                         item.data = [C, keyL, isPPI, extra]
                         C = the core
                         keyL = list of keys
                         isPPI = boolean if TRUE PPI data, else PST
                         extra = [Sender ip_addr, Sender nodePublicKet]
            if I don't know C or I'm not his mirrot forward a DFR
            if I've the data send a DFC as response      
            
        '''
        C, keyL, isPPI, extra,LRDC,requestID = item.data
        if item.isSSLPacket==True:
            extra[0]=item.myIP
        self.logger.info("Incoming DFR from {0} C: {1}".format(binascii.hexlify(item.fromNid[:3]), binascii.hexlify(C[:3])))   
        if C not in self.MRM:
            self.logger.error("receivedDFR: INVALID MATRYOSHKA")
            return
        found = -1 
        #if sender is a nexthop i save it in i
        for i, x in enumerate(self.MRM[C].node_list):
            if x[0] == item.fromNid:
                found = i
                break
        #if i am a prism and the request is not allowed
        if self.MRM[C].node_list != [] and found == -1:
            self.logger.error("receivedDFR: REQUESTER NOT ALLOWED")
            return
        
        #if i dont know C or i know it but i am not his mirror
        if C not in self.FRT or self.FRT[C].cert_node[0] != self.MRM[C].Nid_inh:
            if C not in self.DRM:
                self.lock_data.acquire()
                self.DRM[C] = []
                self.lock_data.release()
            Nid = item.fromNid

            rand_num = 0#requestID
            if self.MRM[C].node_list == []:
                Nid = extra
                item.data[3] = []
            timestamp=int(round(time.time()))
            self.lock_data.acquire()
            self.DRM[C].append(DRE(Nid, requestID))
            self.logger.info( 'adding an entry in DRM_chk for C='+binascii.hexlify(C)+' for reqId='+str(requestID))
            self.DRM_chk[(C,requestID)]=[-1,-1,timestamp]#@Ali Adding an entry for PRR request Path for multple DFC replies
            self.lock_data.release()
            if C not in self.MRM:
                return
            if self.MRM[C].Nid_inh not in self.NUid:
                return 
            key = self.NUid[self.MRM[C].Nid_inh]
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_DFR", item.data, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
            self.logger.info("Sending: {0} "
                             "------ {1} -> {2}".format("S_MAT_DFR", self.myFRE.name[0], self.FRT[key].name[0]))
            return
              
        if len(LRDC)!=0:
            if LRDC[0]=='find':
                self.logger.info( "DFR for find request uid= "+binascii.hexlify(C))
                rows=self.usr_mng.getFDR(binascii.hexlify(C),1)

                print len(rows)
                for row in rows:
                    if len(row)==0:
                        self.logger.info( 'No data in FDR for uid')
                        return
                    uid,did,fcount,kid,es_dtok=row
                    Type,fcount_chk,kid_chk,proplist_all=es_dtok
                    if Type=='PPI':
                        content=['PPI',fcount,0,proplist_all]
                        listdata =[[(binascii.hexlify(C),did,fcount,0,str(b64encode(pickle.dumps(content,2))))]]
                        key = self.NUid[item.fromNid]
                        print self.FRT[key].ip_addr
                        serlized_list=str(b64encode(pickle.dumps(listdata, pickle.HIGHEST_PROTOCOL)))
                        self.logger.info( 'DFR: sending :'+str(len(serlized_list)) )
                        self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_DFC", (C,serlized_list , 'find',(requestID,1)), self.FRT[key].ip_addr,
                                            self.FRT[key].cert_node[1]))
                        self.logger.info("Sending: {0} "
                                         "------ {1} -> {2}".format("S_MAT_DFC", self.myFRE.name[0], self.FRT[key].name[0]))
        
                    else:
                        continue
                return
        if self.usr_mng.dbm.isFDR(binascii.hexlify(C)):
#            print 'i am in DFR loop-1'
            self.logger.info("receivedDFR: I have C's data")  
            if item.fromNid not in self.NUid:
                self.logger.info("ERROR: Cant't send data, impossible to convert node to user id") 
                print "ERROR DFR: Cant't send data, impossible to convert node to user id "
            
                return
#            print 'i am in DFR loop-2'
            key = self.NUid[item.fromNid]
			#@Ali
            self.logger.info( 'response data for uid='+binascii.hexlify(C)+' for LRDC='+str(LRDC)+' keys='+str(keyL))
            if len(LRDC)==0:
                query="SELECT UIDOWNER,DID,FCOUNT,Key_ID,Fr_ESDT FROM FDR WHERE (UIDOWNER='"+binascii.hexlify(C)+"') AND ("
            else:
                query="SELECT UIDOWNER,DID,FCOUNT,Key_ID,Fr_ESDT FROM FDR WHERE (UIDOWNER='"+binascii.hexlify(C)+"' AND"
                for fc in LRDC:
                    query+=' FCOUNT<>'+str(fc)+' And'
                query=query[0:len(query)-3]+') AND ('
            
            for k in keyL:
                query+=' Key_ID=='+str(k)+' OR'
            query=query[0:len(query)-2]+')'    
            try:
                fde_list=self.usr_mng.dbm.executeQuery(query)                
            except:
                self.logger.info('Error in FDR table Reading')
                return

            if len(fde_list)==0 or fde_list==None: #@Ali: No data to send
                self.logger.info( 'No new Data to send...:')
                print 'No new Data to send...:'
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_DFC", (C, str(b64encode(pickle.dumps([], pickle.HIGHEST_PROTOCOL))), 0,(requestID,1)), self.FRT[key].ip_addr,
                                            self.FRT[key].cert_node[1]))
                return

            total=len(fde_list)
            print 'DFR: Sending total='+str(total)+' to='+binascii.hexlify(C)
            for fde in fde_list:
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_DFC", (C, str(b64encode(pickle.dumps([fde], pickle.HIGHEST_PROTOCOL))), 0,(requestID,total)), self.FRT[key].ip_addr,
                                            self.FRT[key].cert_node[1]))
                self.logger.info("Sending: {0} "
                            "------ {1} -> {2}".format("S_MAT_DFC", self.myFRE.name[0], self.FRT[key].name[0]))
            return
        

    def removeFriend( self, uid):
        
        if uid in self.FRT:
            nid = self.FRT[uid].cert_node[0]
        else:
            self.logger.debug("removeFriend: Not one of my friends, BYE")
            return
        #the node to remove is one of my mirrors
        if self.myFRE.cert_user[0] in self.MRM and self.MRM[self.myFRE.cert_user[0]].Nid_inh == nid:
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PRN", self.myFRE.cert_user[0], self.FRT[uid].ip_addr, self.FRT[uid].cert_node[1]))
            self.logger.debug("removeFriend: Sending PRN to uid:"+str(uid.encode('hex')))
        #send MBR to the node
        self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_MBR", "Bye!", self.FRT[uid].ip_addr, self.FRT[uid].cert_node[1]))
        self.logger.debug("removeFriend:Sending: {0} ------ {1} -> {2}".format("S_MAT_MBR", self.myFRE.name[0], self.FRT[uid].name[0]))
        
        #processing a fake mbr from the user to remove
        self.logger.debug("removeFriend: processing bye from uid:"+str(uid.encode('hex')))
        self.receivedMBR(MatMessage(self.FRT[uid].cert_node[0], "S_MAT_MBR", "Bye!", self.myFRE.ip_addr, self.myFRE.cert_node[1]))
        
        #remove from fdr
        
        if self.usr_mng.dbm.isFDR(uid.encode('hex')):
            try:
                self.usr_mng.dbm.delFDR(uid)
            except:
                'Error in FDR Table while deleting'
            self.logger.debug("removeFriend: remove FDR entry")
        #remove from DDR
        #self.logger.debug("removeFriend: remove DDR entry")
        #to_del = []
        #for did in self.DDR.values():
        #        if dde.sf == uid:
        #            to_del.append([did,dde])
       # 
       # for did,dde in to_del:
       #     del self.DDR[did].dde
            
        
        #remove from cta
        self.logger.debug("removeFriend: remove cta_box entry")
        if uid in self.cta_box:
            self.lock_data.acquire()
            del self.cta_box[uid]
            self.lock_data.release()
        #remove from PPI
        self.logger.debug("removeFriend: remove PPI")
        query = str('DELETE FROM PPI WHERE UIDFRIEND="{0}"'.format(str(uid.encode('hex'))))
        #query = "DELETE FROM PPI WHERE uidfriend="+str(uid.encode('hex'))
        self.usr_mng.dbm.executeQuery(query)
        
        #remove from PST
        self.logger.debug("removeFriend: remove PST")
        query = str('DELETE FROM PST WHERE UIDOWNER="{0}" OR UID = "{0}"'.format(str(uid.encode('hex'))))
        self.usr_mng.dbm.executeQuery(query)
        self.lock_data.acquire()
        del self.FRT[uid]
        self.lock_data.release()
        #del self.NUid[nid]
        
        
    def receivedPRS(self,item):
        if self.myFRE.cert_user[0] not in self.MRM:
            self.logger.error("receivedPRS: I've no Matryoshka so I cannot send my profile")
            return
        did,fcount,kid,content=item.data
        C = self.myFRE.cert_user[0]
        DSR=[binascii.hexlify(C),did,fcount,kid,content]
        for x in self.MRM[C].node_list:
            if x[1] == "ESTABLISHED":
                key = self.NUid[x[0]] 
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_DSR", DSR, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
                self.logger.info("Sending: {0} "
                                 "------ {1} -> {2}".format("S_MAT_DSR", self.myFRE.name[0], self.FRT[key].name[0]))  

    def forwardPR(self, C, FEP_L, keyL,LRDC,requestID):
        '''
            forward Profile Request
            @param C: = the core uid
            @param FEP_L: = entry point list
            @param keyL: = list of keys
            @param isPPI: = boolean, True = is a PPI request, False = is a PST request
                            
            send a DFR Data Fetch request to each entry point
        '''
        for x in FEP_L:
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_DFR", [C, keyL, 0, [self.myFRE.ip_addr, self.myFRE.cert_node[1]],LRDC,requestID], x.ip_addr, x.cert_node[1]))
            self.logger.info("Sending: {0} "
                          "------ {1} -> {2}".format("S_MAT_DFR", self.myFRE.name[0], x.ip_addr))
    
    def receivedPRR(self, item):
        '''
            Received Profile Retrival Request
            @param item: ( a MatMessage defined in Messages)
                        item.data = dht lookup key
                        
            creates the entry in DRM for the key (deleted in received DFC)
            perform a recursive find in the P2P for that key
            if the recursive find an entry point, call forwardPR (it chooese random if ask for PPI or PST data)

        '''
        print 'Retrieving new data of '+str(self.FRT[item.data].name)
        if not self.running:
            return
        myNid = self.myFRE.cert_node[0]
        dhtlk = item.data
        self.lock_data.acquire()
        if dhtlk not in self.DRM:
            self.DRM[dhtlk] = []
        requestId=random.randint(1,100000000)
        self.DRM[dhtlk].append(DRE(myNid, requestId))
        self.lock_data.release()
        def ep_values(items):
            
            deleted = False
            for item in items:
                reg_tok, cert_node, ip_addr,  time_v, isSSL = item
                reg_tok_data = reg_tok[0]
                ret_sign = reg_tok[1]
                cert_dhtlk, a = reg_tok_data
                cert_user, ExpireTime = a
                ret_dhtlk, ret_pkeyk, k_sign  = cert_dhtlk
                ret_Uid, ret_pkeyU, u_sign  = cert_user
                
                data = pickle.dumps(reg_tok, 2)
                crypto.verify_sign(ret_pkeyU, data, ret_sign)
                self.lock_data.acquire()
                if ret_Uid not in self.FET:
                    self.FET[ret_Uid] = []
                self.FET[ret_Uid].append(FEP(cert_node, ip_addr, time_v, ExpireTime,isSSL))
                if ret_dhtlk != ret_Uid:
                    if deleted == False:
                        del self.DRM[dhtlk]
                        deleted = True
                    if ret_Uid not in self.DRM:
                        self.DRM[ret_Uid] = []
                    self.DRM[ret_Uid].append(DRE(self.myFRE.cert_node[0], 0))
                    
                self.lock_data.release()
            epL = self.FET[ret_Uid][:self.ep_alpha]
            
            LRDC_db=self.usr_mng.dbm.getFCountRDR(binascii.hexlify(ret_Uid))
            
            LRDC=[]
            for lr in LRDC_db:
                LRDC.append(lr[0])
            print LRDC
            query="SELECT Key_ID FROM FDD WHERE UIDOWNER = '"+binascii.hexlify(ret_Uid)+"'"
            keys=[0]
            try:
                keys_db=self.usr_mng.dbm.executeQuery(query)
                for k in keys_db:
                    keys.append(k[0])
            except:
                self.logger.info('Error in FDD table Reading')
                keys=[0]
            
            self.logger.info( 'request data for uid='+binascii.hexlify(ret_Uid)+' for LRDC='+str(LRDC)+' keys='+str(keys)  )
            
            timestamp=int(round(time.time()))
            self.logger.info( 'adding an entry in DRM_chk for C='+binascii.hexlify(dhtlk)+' for reqId='+str(requestId))
            self.lock_data.acquire()
            self.DRM_chk[(dhtlk,requestId)]=[-1,-1,timestamp]
            self.lock_data.release()
            
            self.forwardPR(ret_Uid, epL, keys,LRDC,requestId)
        def ep_not_found(result):
            self.logger.info("Entry point not found!") 
            pass
        df = self.main_mng.p2p.recursiveFind2(dhtlk)
        df.addCallback(ep_values)
        df.addErrback(ep_not_found)

    def receivedDSR(self,item):
        if item.fromNid not in self.NUid:
            return
        
        C = self.NUid[item.fromNid]
        if C not in self.MRM or item.fromNid != self.MRM[C].Nid_inh:
            return
        uid,did,fcount,kid,content=item.data
        try:
            self.usr_mng.dbm.addupdateFDR(uid,did,fcount,kid,content)
        except:
            self.logger.info( 'Error writing in FDR Table')
            self.logger.info( traceback.print_exc())
            return
        key = C
        self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_DSC", (self.myFRE.cert_user[0],did,fcount), self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
        self.logger.info("Sending: {0} "
                     "------ {1} -> {2}".format("S_MAT_DSC", self.myFRE.name[0], self.FRT[key].name[0]))

        
                                
    def receivedDSC(self, item):
        '''
            Received Data Store Confirmation
            @param    item: ( a MatMessage defined in Messages)
                         item.data = (kid, id, count)
        '''
        uid,did,fcount=item.data
        self.usr_mng.dbm.addDDR(uid,did,fcount)
        self.logger.info("receivedDSC: Data Stored")
            
    def reboot(self, C):
        '''
            reboot the Matryoshka
            @param C: the Matryoshka core

            try to replace next hop for C and call the mirror control on the nexthop

        '''
        if not self.running:
            print "REBOOT ERROR - not running"
            return
        if C not in self.MRM:
            print "REBOOT ERROR - C not in MRM"
            return
        self.logger.info("Matryoshka reboot")
        
        to_contact = len(self.MRM[C].node_list)
        self.MRM[C].node_list = []
        while to_contact > 0:
            Nidx= self.replaceNH(C)
            # if no replacement but at least one est. or pend
            if Nidx==0:
                return
            # if no way to replace, reboot again
            if not Nidx:
                print 'rebooting again'
                self.reboot(C)  
                return
            to_contact -=1 
            self.mirror_control(Nidx)
         

    def FAControl(self,Nidx):
        result = self.get_CTA(Nidx)
        #result = self.usr_mng.dbm.popFAT(binascii.hexlify(Nidx))
        if result is None:
            self.logger.debug("No CTA stored for nid:"+str(Nidx.encode('hex')))
            return
        if Nidx not in self.NUid:
            return
        key = self.NUid[Nidx]
        if key not in self.FRT:
            return
        for elm in result:
            self.logger.debug("sending CTA from database to target: "+str(key.encode('hex')))
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_CTA", elm, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
    
    def mirror_control(self,Nidx):
        '''
            mirror control
            @param Nidx: the node id to wich send the PCR
            @return: -1 failure, 0 no need to send a PCR, 1 PCR sent
        '''
        if not self.running:
            return -1
        
        Uid = self.myFRE.cert_user[0]
        if Uid not in self.MRM:
            self.MRM[Uid] = MRC(None, [], None)
        i = 0
        found_Nidx = -1
        for k, x in enumerate(self.MRM[Uid].node_list):
            if x[0] == Nidx:
                found_Nidx = k 
        if found_Nidx == -1:
            self.MRM[Uid].node_list.append([Nidx, "ACK_PENDING"])
        else:
            print "MIRRORCONTROL - nh already in the nhList"
            return 0
           # self.MRM[Uid].node_list[found_Nidx][1] = "ACK_PENDING"
        
        
        
        
        num = struct.Struct("!B")
        TtlMatr = array.array('c')
        TtlMatr.extend(num.pack(1) + crypto.sign(self.keys, num.pack(1)))
        for i in range(2, self.max_ttl + 1):
            TtlMatr.extend(num.pack(i))
            sign = crypto.sign(self.keys, TtlMatr.tostring())
            TtlMatr.extend(sign)
        TtlMatr = TtlMatr.tostring()
        RegTok_data = (self.cert_dhtlkeys, self.myFRE.cert_user, self.ExpireTime)
 
        RegTok_sign = []       
        for cert in self.cert_dhtlkeys:
            tmp = (cert, RegTok_data[1:])
            to_sign = pickle.dumps(tmp, 2)
            RegTok_sign.append(crypto.sign(self.keys, to_sign))


        RegTok = (RegTok_data, RegTok_sign)

        Span_data = self.span
        Span_sign = crypto.sign(self.keys, struct.pack("!B", Span_data))
        Span = (Span_data, Span_sign)

        Rnd_data = random.randint(0, 50)
        Rnd_sign = crypto.sign(self.keys, struct.pack("!B", Rnd_data))
        Rnd = (Rnd_data, Rnd_sign)

        PCR = [RegTok, TtlMatr, Span, Rnd]
        
        if Uid in self.MRM:
            self.MRM[Uid].pcr = PCR
        
        if Nidx not in self.NUid:
            print "MIRROR CONTROL ERROR - unable to translate Nid->Uid"
            return -1
        
        key = self.NUid[Nidx]
        if key not in self.FRT:
            print "MIRROR CONTROL ERROR - nh is not a friend"
            return -1
        self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCR", PCR, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
        self.logger.info("sending PCR: {0} "
                        "------ {1} -> {2}, C: {3}, TTL: {4}".format("S_MAT_PCR", self.myFRE.name[0], self.FRT[key].name[0], 
                                                                        binascii.hexlify(Uid[:3]), binascii.hexlify(TtlMatr[::65])))  
        return 1 

    
    
        
    def sendMHR(self, x):
        '''
            Send Matryoshka hello request
            @param x: the node i to wich send the hello          
            send a MAT_MHR
        '''
        item=MatMessage(self.myFRE.cert_node[0], "S_MAT_MHR", "Hello!", x.ip_addr, x.cert_node[1])
        item.myIP=(myPubaddr[0],myPubaddr[1],myPubaddr[2])#@Ali
        self.main_mng.add(item)
        self.logger.info("Sending {0} "
                         "------ {1} -> {2} ".format("S_MAT_MHR", self.myFRE.name[0], x.ip_addr))
                             
    def receivedMHR(self, item):
        '''
            Received Matryoshka hello request
            @param tem: ( a MatMessage defined in Messages)
            
            get the nid from the item,
            check if is in my NUid, if yes get the uid
            set that user online in my frt, save his ip address in my FRT and send him a MAT_MHC (matryoshka hello confirmation)       
            if is not one of my friend print FAKE STATE !!!
        '''
        try:
            if item.fromNid not in self.NUid:
                print "ERROR: sender node "+str(item.fromNid.encode('hex'))[:4] +" not in NUid"
                return
            key = self.NUid[item.fromNid]
 #TONY           
            if key in self.FRT:
                print "sender's status is " + str(self.FRT[key].status)
                if self.FRT[key].status != "FRIENDSHIP_RECEIVED":
                    self.lock_data.acquire()
                    self.FRT[key].online = True
                    self.FRT[key].ip_addr = item.myIP#@Ali
                    self.lock_data.release()
                    self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_MHC", "I'm alive too!", self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
                    self.logger.info("Sending: {0} "
                          "------ {1} -> {2} ({3})".format("S_MAT_MHC", self.myFRE.name[0], self.FRT[key].name[0], self.FRT[key].ip_addr))
                    key = self.NUid[item.fromNid]
                    if self.FRT[key].status != "FRIENDSHIP_SENT":       
                        self.mirror_control(item.fromNid)
                    self.FAControl(item.fromNid)
                else:
                    print "received MHR from Unrecognized friend"
                    self.logger.info("received MHR from UNRECOGNIZED FRIEND!")
            else:
                print "received MHR from Unknown friend: " + binascii.hexlify(item.fromNid)
                self.logger.info("received MHR from UNKNOWN FRIEND!")
        except:
            #e,d,t=sys.exc_info()
            #traceback.print_tb(t)
            self.logger.error("FAKE STATE!!!:")

    def receivedMHC(self, item):
        '''
            Received Matryoshka hello Confirmation
            @param tem: ( a MatMessage defined in Messages)
            
            get the nid from the item,
            check if is in my NUid, if yes get the uid
            set that user online in my frt, save his ip address in my FRT
            if the friendship is estabilished perform a mirror control on his node id 
        '''
        if item.fromNid not in self.NUid:
            return
        key = self.NUid[item.fromNid]
        if key in self.FRT:
            self.FRT[key].online = True
            if self.FRT[key].status != "FRIENDSHIP_SENT":       
                self.mirror_control(item.fromNid)
            self.FAControl(item.fromNid)
        else:
            self.logger.info("received MHC from UNKNOWN FRIEND!")
            
    def unregister_as_ep(self):
        ''''
            unregister myself as entrypoint so remove from p2p all the keys for which I'm entrypoint
        '''
        for Cuid in self.MRM:
            if self.MRM[Cuid].node_list == []:
                print "................unregistering as an entrypoint of "+str(Cuid.encode('hex'))
                self.logger.debug("unregister_as_ep: I'm the Entrypoint for uid:"+str(Cuid.encode('hex')))
                #I'm the entrypoint for C and an innerhop is leaving
                #remove entrypoint request for P2P
                #get the pcr from MRM
                pcr = self.MRM[Cuid].pcr
                #pcr = [RegTok, TtlMatr, Span, Rnd] -> RegTok = pcr[0]
                #RegTok = (RegTok_data, RegTok_sign) -> RegTok_data = pcr[0][0]
                #RegTok_data = (self.cert_dhtlkeys, self.myFRE.cert_user, self.ExpireTime) -> self.cert_dhtlkey = RegTok_data[0] 
                RegTok_data = pcr[0][0]
                cert_list = RegTok_data[0]
                for cert in cert_list:
                    #cert = (hash,uPublickey,signature) --> key = cert[0]
                    key = cert[0]
					
                    if tuple([key,Cuid]) in self.iAmEntryPointOf.keys():
                        print "............ i was an entrypoint of "+str(binascii.hexlify(Cuid))[0:4]
                        self.main_mng.add(MatMessage(None, "R_P2P_UER", (key,self.iAmEntryPointOf[str(binascii.hexlify(key)),str(binascii.hexlify(Cuid))]), None, None))
                        self.logger.info("Sending: R_P2P_UER") #Unpublish entry poinr
                    else:
                        print "ERROR: i'm trying to deregister as an entrypoint of "+str(binascii.hexlify(Cuid))[0:4]+" for a key"+str(binascii.hexlify(key))[0:4]+" i never registered!!"

    
    def sendMBR(self):
        '''
            send Matryoshka Bye Request
            send a Bye request to all my friends which are online MAT_MBR
        ''' 
        self.lock_data.acquire()
        for key, x in self.FRT.items():
            if x.online:
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_MBR", "Bye!", x.ip_addr, x.cert_node[1]))
                self.logger.info("Sending: {0} "
                             "------ {1} -> {2}".format("S_MAT_MBR", self.myFRE.name[0], x.name[0]))
        self.lock_data.release()
    def receivedMBR(self, item):
        '''
            received Matryoshka Bye Request
            @param item: ( a MatMessage defined in Messages)
            get the nid from the item
            check if is one of my friend and set it offline
            for each entry in MRM check the role of the leaving node
            leavingnode == core -> do nothing and keep the Matryoshka
            leavingnode == outerhop -> try to replace sending PCR to the replacement node
                                        if no replacement found: 
                                            if I'm the core -> reboot
                                            else send a MAT_PCF path creation failure
                                            
            leaving node == innerhop -> if I'm the entrypoint (unpublish key) P2P_UER for each key
                                        if I'm a prism send S_MAT_PRN (prune) to all the node in node_list
            delete the entry from MRM
        '''
        toReboot=False
        if not self.running:
            return
        leavingNid = item.fromNid
        if leavingNid not in self.NUid:
            return
        leavingUid = self.NUid[leavingNid]
        self.logger.debug("Received MBR from uid:"+str(leavingUid.encode('hex')+" nid:"+str(leavingNid.encode('hex'))))
        #if is one of my friends
        if leavingUid in self.FRT:
            self.lock_data.acquire()
            self.FRT[leavingUid].online = False
            self.logger.debug("It's one of my friends, Setting it offline")
            self.lock_data.release()
            #check for every node in MRM if the leaving node is previous or next hop
            to_del = []
            for Cuid in self.MRM:
                
                #if the leaving node is one node of the list
                exist = False
                for x in self.MRM[Cuid].node_list:
                    if x[0] == leavingNid:
                        exist = True
                        
                self.logger.debug("In MRM of:"+str(Cuid.encode('hex')))
                #if the leaving node is previous hop of the current Cuid
                if leavingNid == self.MRM[Cuid].Nid_inh:
                    self.logger.debug("It's inner hop for MRM of:"+str(Cuid.encode('hex')))
                    #inner hop leaving
                    #if the leaving node is the core itself
                    if leavingUid == Cuid:
                        self.logger.debug("It's the core itself for MRM of:"+str(Cuid.encode('hex')))
                        #core leaving
                        #to_del.append(Cuid)
                    else:
                        self.logger.debug("It's Not the core for MRM of:"+str(Cuid.encode('hex')))
                        #if the node list is empty "leaving node == self.MRM[Cuid].Nid_inh => I'm the entry point for Cuid
                        
                        if self.MRM[Cuid].node_list == []:
                            self.logger.debug("I'm the entrypoint for MRM of:"+str(Cuid.encode('hex')))
                            #I'm the entrypoint for C and an innerhop is leaving
                            #remove entrypoint request for P2P
                            
                            #get the pcr from MRM
                            pcr = self.MRM[Cuid].pcr
                            #pcr = [RegTok, TtlMatr, Span, Rnd] -> RegTok = pcr[0]
                            #RegTok = (RegTok_data, RegTok_sign) -> RegTok_data = pcr[0][0]
                            #RegTok_data = (self.cert_dhtlkeys, self.myFRE.cert_user, self.ExpireTime) -> self.cert_dhtlkey = RegTok_data[0] 
                            RegTok_data = pcr[0][0]
                            cert_list = RegTok_data[0]
                            for cert in cert_list:
                                #cert = (hash,uPublickey,signature) --> key = cert[0]
                                key = cert[0]
								# FIXME TONY
                                if tuple([key,Cuid]) in self.iAmEntryPointOf.keys():
                                    print "............ i was an entrypoint of "+str(binascii.hexlify(Cuid))[0:4]
                                    self.main_mng.add(MatMessage(None, "R_P2P_UER", (key,self.iAmEntryPointOf[str(binascii.hexlify(key)),str(binascii.hexlify(Cuid))]), None, None))
                                    self.logger.info("Sending: R_P2P_UER") #Unpublish entry poinr
                                else:
                                    print "ERROR: i'm trying to deregister as an entrypoint of "+str(binascii.hexlify(Cuid))[0:4]+" for a key"+str(binascii.hexlify(key))[0:4]+" i never registered!!"
                        else:
                            self.logger.debug("I'm a prism in MRM of:"+str(Cuid.encode('hex'))+" sending prune to all the node in the list")
                            #send Prune request to each node in next hop list
                            for n_h in self.MRM[Cuid].node_list:
                                # n_h = [Nid,'status']
                                #nodeId to prune
                                pruningNid = n_h[0]
                                
                                #userId to prune 
                                if pruningNid not in self.NUid:
                                    pass
                                else:
                                    pruningUid = self.NUid[pruningNid]
                                    self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PRN", Cuid, self.FRT[pruningUid].ip_addr, self.FRT[pruningUid].cert_node[1]))
                                    self.logger.info("Sending: {0} "
                                                     "------ {1} -> {2}".format("S_MAT_PRN", self.myFRE.name[0], self.FRT[pruningUid].name[0]))
                                #After remove the MRM entry for this Cuid
                        
                        #remove the MRM entry for this Cuid
                        self.logger.debug("delete MRM entry for uid:"+str(Cuid.encode('hex')))
                        to_del.append(Cuid)
                        #return
                #if the leaving node is one node of the list
                elif exist:
                    self.logger.debug("outer hop leaving for MRM :"+str(Cuid.encode('hex')))
                    #outer hop leaving
                    #check if there is at least one replace nexht hop
                    next_hop_replacement_nid = self.replaceNH(Cuid)
# TONY
                    if next_hop_replacement_nid != None and next_hop_replacement_nid != 0:
                        self.logger.debug("I found a nexthop replacement nid:"+str(next_hop_replacement_nid.encode('hex'))+" for uid:"+str(Cuid.encode('hex')))
                        self.MRM[Cuid].node_list.append([next_hop_replacement_nid, "ACK_PENDING"])
                        pcr = self.MRM[Cuid].pcr
                        #in this pcr ttl has already been decremented by  one in (receivedPCR , forward PCR)
                        next_hop_replacement_uid = self.NUid[next_hop_replacement_nid]
                        
                        self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCR", pcr, self.FRT[next_hop_replacement_uid].ip_addr, self.FRT[next_hop_replacement_uid].cert_node[1]))
                        self.logger.info("forwarding : {0} "
                                         "------ {1} -> {2}, C: {3}".format("S_MAT_PCR", self.myFRE.name[0], self.FRT[next_hop_replacement_uid].name[0], 
                                                                                  binascii.hexlify(Cuid[:3])))
                        #remove the leaving nid from the list of Cuid
                        self.logger.debug("Remove the leaving nid from the list of node in MRM of:"+str(Cuid.encode('hex')))
                        i = 0
                        for el in self.MRM[Cuid].node_list:
                            if el[0] == leavingNid:
                                del self.MRM[Cuid].node_list[i]
                                
                            i += 1
                    else:
                        self.logger.debug("nexthop replacement failed")
                        #replaceNH failed
                        #if Cuid == myUid (It's one of my Matryoshka)
#TONY
                        if Cuid == self.myFRE.cert_user[0]:
                        
                            if next_hop_replacement_nid == None:
                                self.logger.debug("Leaving Node is one of my mirrors, and i don't have pend. or est. chains, I'm Rebooting")
                            #reboot my matryoshka ( to DO: check reboot)
                                myU=Cuid
                                toReboot=True
                                
                            else:
                                self.logger.debug("Leaving Node is one of my mirrors, but i have at least a pend. or est. chain, I'm not rebooting")
                                # delete nh from nhlist
                                i = 0
                                for el in self.MRM[Cuid].node_list:
                                    if el[0] == leavingNid:
                                        del self.MRM[Cuid].node_list[i]
                                    i += 1
                                pass
                        else:
                            self.logger.debug("Cuid is NOT one of my mirrors")
                            if (self.NUid[self.MRM[Cuid].Nid_inh] == Cuid and self.FRT[Cuid].online) or self.NUid[self.MRM[Cuid].Nid_inh] != Cuid :
                                self.logger.debug("I'm mirror for Cuid:"+str(Cuid.encode('hex'))+" and he is online, or prism of Cuid, I cannot replace his outerhop, send PCF")
                                previous_hop_nid = self.MRM[Cuid].Nid_inh
                                previous_hop_uid = self.NUid[previous_hop_nid]
                                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCF", Cuid, self.FRT[previous_hop_uid].ip_addr, self.FRT[previous_hop_uid].cert_node[1]))
                                #self.logger.info("Sending: {0} ------ {1} -> {2}".format("S_MAT_PCF", self.myFRE.name[0], self.FRT[previous_hop_uid].name[0])
                                
                            else:
                                self.logger.debug("I'm a mirror, the core is offline, I won't advertise the core with PCF")
                                #I'm a mirror, the core is offline, I won't advertise the core with PCF (since it's offline)
                                pass
                            self.logger.debug("Remove the MRM entry for:"+str(Cuid.encode('hex')))
                            to_del.append(Cuid)
                                
                else:
                    self.logger.debug("No role for leaving node for Cuid's Matryoshka")
                    #not role for leaving node for Cuid's MAtryhoska
                    pass
            for e in to_del:
                del self.MRM[e]
        else:
            self.logger.debug("received MBR from UNKNOWN FRIEND!")
            return
        
        if toReboot==True:
            self.reboot(myU)

    def receivedPRN(self,item):
        '''
            Received PRN Prune Request
            @param item: ( a MatMessage defined in Messages)
                        item.data = C core uid
            get the nid from the item,
            
            check if the core is in my MRM
                if I'm an entry point (unpublish) R_P2P_UER
                
                if I'm a prism forward the prune to the other nodes in node_list
        '''
        sender_nid = item.fromNid
        if sender_nid not in self.NUid:
            self.logger.info("received PRN- incorrect nid sender")
            return
        
        sender_uid = self.NUid(sender_nid)
        if sender_uid not in self.FRT:
            self.logger.info("received PRN- incorrect uid sender")
            return
        Cuid = item.data
        
        if Cuid not in self.MRM:
            self.logger.info("received PRN - incorrect Cuid , not in my MRM")
            return
        
        if self.MRM[Cuid].node_list == []:
            pcr = self.MRM[Cuid].pcr
            #pcr = [RegTok, TtlMatr, Span, Rnd] -> RegTok = pcr[0]
            #RegTok = (RegTok_data, RegTok_sign) -> RegTok_data = pcr[0][0]
            #RegTok_data = (self.cert_dhtlkeys, self.myFRE.cert_user, self.ExpireTime) -> self.cert_dhtlkey = RegTok_data[0] 
            RegTok_data = pcr[0][0]
            cert_list = RegTok_data[0]
            for cert in cert_list:
                #cert = (hash,uPublickey,signature) --> key = cert[0]
                key = cert[0]
			
                if tuple([key,Cuid]) in self.iAmEntryPointOf.keys():
                    print "............ i was an entrypoint of "+str(binascii.hexlify(Cuid))[0:4]
                    self.main_mng.add(MatMessage(None, "R_P2P_UER", (key,self.iAmEntryPointOf[str(binascii.hexlify(key)),str(binascii.hexlify(Cuid))]), None, None))
                    self.logger.info("Sending: R_P2P_UER") #Unpublish entry poinr
                else:
                    print "ERROR: i'm trying to deregister as an entrypoint of "+str(binascii.hexlify(Cuid))[0:4]+" for a key"+str(binascii.hexlify(key))[0:4]+" i never registered!!"

        else:
            #is not empty so forward prn to all the nodes
            for n_h in self.MRM[Cuid].node_list:
                # n_h = [Nid,'status']
                #nodeId to prune
                pruningNid = n_h[0]
                                
                #userId to prune 
                pruningUid = self.NUid[pruningNid]
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PRN", Cuid, self.FRT[pruningUid].ip_addr, self.FRT[pruningUid].cert_node[1]))
                self.logger.info("Sending: {0} "
                                 "------ {1} -> {2}".format("S_MAT_PRN", self.myFRE.name[0], self.FRT[key].name[0]))
        
        #delete the MRM entry

        del self.MRM[Cuid]

        return

    def receivedPCR(self, item):
        '''
            received Path creation request
            @param item: ( a MatMessage defined in Messages)
                        item.data = [[RegTok_data, RegTok_sign], TtlMatr,[desired_span]]
            if is valid
            and if I can build a path for the Core
            decrement the TtlMatr and save the PCR in MRM
            if I'm the entry point
                send a MAY (Matryoshka ack yes)
                pulish p2p data P2P_PER
            else forward PCR
            
            if I cannot build a path MAT_MAN
             
        '''
        
        if item.data is None:
            self.logger.info("received PCR: ALERT!!!!!!! NONE")
        if item.fromNid not in self.NUid:
            return
        key = self.NUid[item.fromNid]
        if key not in self.FRT or self.FRT[key].status == "FRIENDSHIP_RECEIVED":
           self.logger.info("received PCR: PCR DENIED")
           return
        
        try:         
            RegTok_data = item.data[0][0]
            RegTok_sign = item.data[0][1]
        except IndexError:
            TtlMatr = item.data[1]
            
        cert_user = RegTok_data[1]
        C = cert_user[0]
        if C in self.MRM:
            if self.NUid[self.MRM[C].Nid_inh] == C and C == key :
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_MAY", C, self.FRT[C].ip_addr, self.FRT[C].cert_node[1]))
                self.logger.info("I'm the entry point\nSending: {0} "
                                 "------ {1} -> {2}".format("S_MAT_MAY", self.myFRE.name[0], self.FRT[C].name[0]))
                self.logger.debug("The core"+str(C.encode('hex'))+" is online again and he sent me a pcr, I'm his mirror")
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCC", C, self.FRT[C].ip_addr, self.FRT[C].cert_node[1]))
                self.logger.info("Sending: {0} "
                                 "------ {1} -> {2}".format("S_MAT_PCC", self.myFRE.name[0], self.FRT[C].name[0]))
                return
            else:
                self.logger.debug("Hit in MRM for C"+str(C.encode('hex'))+ " but i'm not the mirror")
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_MAN", C, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
                self.logger.info("Sending: {0} "
                                 "------ {1} -> {2}".format("S_MAT_MAN", self.myFRE.name[0], self.FRT[key].name[0]))
                return        
                 
        pkey = cert_user[1]
        TtlMatr = item.data[1]
        data = TtlMatr[:-64]
        sig = TtlMatr[-64:]
        if not crypto.verify_sign(pkey, data, sig):
            self.logger.info("received PCR: TTL verification FAILED!")

        New_TtlMatr = data[:-1]
        item.data[1] = New_TtlMatr
        if len(New_TtlMatr) == 0:
            if self.sslClientOnly==True:
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_MAN", C, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
                print 'SSLClient, I cannot be an entry point'
                self.logger.info("I'm SSLClient, I cannot be an entry point, sending  {0} "
                          "------ {1} -> {2}".format("S_MAT_MAN", self.myFRE.name[0], self.FRT[key].name[0]))
                return
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_MAY", C, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
            self.logger.info("I'm the entry point\nSending: {0} "
                      "------ {1} -> {2}".format("S_MAT_MAY", self.myFRE.name[0], self.FRT[key].name[0]))
            
            new_MRC = MRC(item.fromNid, [], item.data)
            self.MRM[C] = new_MRC
            cert_list = RegTok_data[0]
            for cert, sign in zip(cert_list, RegTok_sign):
                key = cert[0]
                reg_tok = ((cert, RegTok_data[1:]), sign)
                value = (reg_tok, self.myFRE.cert_node, self.myFRE.ip_addr,  time.time(),self.isSSL)
#                if self.sslClientOnly==False:#@Ali: Client on ssl Support dont take part in p2p overlay
                time.sleep(random.randrange(1,4,1))
                print "------> storing <"+str(key.encode('hex'))[:4]+", my node cert> in the p2p system for core"+str(C.encode('hex'))[:4]
                self.main_mng.add(MatMessage(None, "R_P2P_PER", (key, value), None, None))
                self.logger.info("Sending: R_P2P_PER -"+str(key))
                print "Registering key "+str(binascii.hexlify(key))[0:4]+" for user "+str(binascii.hexlify(C))[0:4]
                self.iAmEntryPointOf[str(binascii.hexlify(key)),str(binascii.hexlify(C))]=value
            return

        NHlist = []
        #TONY
        
        nodes = [x for x in self.FRT.values() if x.online and x.cert_node[0] != item.fromNid and x.status == "FRIENDSHIP_ESTABLISHED"]

        num_nodes = len(nodes)        
        desired_span = item.data[2][0]
        if num_nodes - desired_span < 0:
            #time.sleep(1)
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_MAN", C, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
            self.logger.info("Sending: {0} "
                            "------ {1} -> {2}".format("S_MAT_MAN", self.myFRE.name[0], self.FRT[key].name[0]))
            return
            
        self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_MAY", C, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
        self.logger.info("Sending: {0} "
                        "------ {1} -> {2}".format("S_MAT_MAY", self.myFRE.name[0], self.FRT[key].name[0]))
             
        sorted_nodes = sorted(nodes, key=lambda x: x.trust)[:desired_span]
        nodes_list = [[x.cert_node[0], "ACK_PENDING"] for x in sorted_nodes]
        new_MRC = MRC(item.fromNid, nodes_list, item.data)    
        self.MRM[C] = new_MRC
        for x in nodes_list:
            Nid = x[0]
            key = self.NUid[Nid]
            #t = threading.Timer(self.ack_time, timer, args=(self.main_mng, Uid, Nid, "ACK_PENDING"))
            #t.start()
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCR", item.data, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
            self.logger.info("forwarding : {0} "
                            "------ {1} -> {2}, C: {3}, TTL: {4}".format("S_MAT_PCR", self.myFRE.name[0], self.FRT[key].name[0], 
                                                                         binascii.hexlify(C[:3]), binascii.hexlify(New_TtlMatr[::65])))        
                
    def receivedPCC(self, item):
        '''
            received Path creation Confirmation
            @param item: ( a MatMessage defined in Messages)
                        item.data = [[RegTok_data, RegTok_sign], TtlMatr,[desired_span]]

        '''
        if item.fromNid not in self.NUid:
            return
        key = self.NUid[item.fromNid]
        if key not in self.FRT or self.FRT[key].status == "FRIENDSHIP_RECEIVED":
            self.logger.error("received PCC: PCC DENIED!")
            return
        C = item.data
        if C not in self.MRM:
            return
        for x in self.MRM[C].node_list:
            if x[0] == item.fromNid:
                if x[1] != "RES_PENDING":
                    return
                x[1] = "ESTABLISHED"
                break
        if C == self.myFRE.cert_user[0]:
            print 'I HAVE BUILT MY MATRYOSHKA!'
            
            self.usr_mng.sendProfileTostore()
            return
        if (C == self.NUid[self.MRM[C].Nid_inh] and self.FRT[C].online) or C != self.NUid[self.MRM[C].Nid_inh]:
            key = self.NUid[self.MRM[C].Nid_inh]
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCC", C, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
            self.logger.info("Sending: {0} "
                            "------ {1} -> {2}".format("S_MAT_PCC", self.myFRE.name[0], self.FRT[key].name[0]))

    def replaceNH(self, C):
    
        '''
            replace next hop
            @param C: the core of the matryoshka the current node has to find a next-hop replacement for
            @return: -1 failure; 0 impossible to find a new replacement, but not needed; 1 PCR sent
        '''
    
        if C not in self.MRM:
            print 'ReplaceNH Error - C is not in MRM'
            return -1
        #all the node id in the list for C
        a = set([x[0] for x in self.MRM[C].node_list])
        a = a.union([self.MRM[C].Nid_inh])
        if C in self.FRT:
            #C's node id
            a  = a.union([self.FRT[C].cert_node[0]])

        # b = set of friend's Nid in FRT
        b = set([x.cert_node[0] for x in self.FRT.values() if x.online and x.status == "FRIENDSHIP_ESTABLISHED"])
        b -= a
        
        if len(b) == 0:
            found = False
            for x in self.MRM[C].node_list:
                if x[1] == "RES_PENDING" or x[1] == "ESTABLISHED" or x[1] == "ACK_PENDING":
                    found = True
                    break
            # No replacement has been found!        
            if not found:
                return None
            else:
                #no replacement has been found, but at least one pending or est.
                return 0
        # A replacement has been found
        else:
            nodes = sorted(list(b), key=lambda x: self.FRT[self.NUid[x]].trust)
            return nodes[0]
     
    def receivedMTO(self, item):
        C, Nid, status = item.data
        if C not in self.MRM:
            return
        try:
            i = self.MRM[C].node_list.index([Nid, status])
            self.MRM[C].node_list[i][1] = "TIMEOUT"
            newNH = self.replaceNH(C)
            if not newNH:
                if C == self.myFRE.cert_user[0]:
                    self.reboot(C)
                    return
                Nid = self.MRM[C].Nid_inh
                del self.MRM[C]
                if (C == self.NUid[Nid] and self.FRT[C].online) or C != self.NUid[Nid]:
                    key = self.NUid[Nid]
                    self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCF", C, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
                    self.logger.info("Sending: {0} "
                                    "------ {1} -> {2}".format("S_MAT_PCF", self.myFRE.name[0], self.FRT[key].name[0]))                         
            else:
                found = False
                for j, x in enumerate(self.MRM[C].node_list):
                    if x[0] == newNH:
                        self.MRM[C].node_list[j][1] = "ACK_PENDING"
                        found = True
                        break
                if not found:
                    self.MRM[C].node_list.append([newNH, "ACK_PENDING"])
                #t = threading.Timer(self.ack_time, timer, args=(self.main_mng, C, newNH, "ACK_PENDING"))
                #t.start()
                key = self.NUid[newNH]
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCR", self.MRM[C].pcr, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
                self.logger.info("Sending: {0} "
                            "------ {1} -> {2}, C: {3}, TTL: {4}".format("S_MAT_PCR", self.myFRE.name[0], self.FRT[key].name[0], 
                                                                         binascii.hexlify(C[:3]), binascii.hexlify(
                                                                         self.MRM[C].pcr[1][::65])))        
                    
        except ValueError:
            pass

    def receivedMAN_PCF(self, item, type):
        if item.fromNid not in self.NUid:
            return
        key = self.NUid[item.fromNid]
        if key not in self.FRT or self.FRT[key].status != "FRIENDSHIP_ESTABLISHED":
            self.logger.info("receivedMAN_PCF: UNKNOWN FRIEND!")
            return
        C = item.data
        found = False
        if C not in self.MRM:
            return
        for x in self.MRM[C].node_list:
            if x[0] == item.fromNid:
                found = True
        if not found:
            self.logger.info("receivedMAN_PCF:  MSG_TYPE: {0}".format(type))
            #print "\nreceivedMAN_PCF(),  MSG_TYPE: {0}".format(type)
        for i, x in enumerate(self.MRM[C].node_list):
            if x[0] == item.fromNid:
                if x[1] == "ACK_PENDING" and type == "MAN":
                    self.MRM[C].node_list[i][1] = "REFUSED"
                elif (x[1] == "RES_PENDING" or x[1] == "ESTABLISHED" ) and type == "PCF":    
                    self.MRM[C].node_list[i][1] = "FAILED"
                else:
                    self.logger.info("\nreceivedMAN_PCF(): STATUS ERROR")
                
        newNH = self.replaceNH(C)
        if not newNH or newNH==0:
            #FAILURE
            if C == self.myFRE.cert_user[0]:
                if newNH!=0:
                    self.reboot(C)
                return
            Nid = self.MRM[C].Nid_inh
            del self.MRM[C]
            if (C == self.NUid[Nid] and self.FRT[C].online) or C != self.NUid[Nid]:
                key = self.NUid[Nid]
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCF", C, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
                self.logger.info("Sending: {0} "
                                "------ {1} -> {2}".format("S_MAT_PCF", self.myFRE.name[0], self.FRT[key].name[0]))                         
        else:
            #SUCESS
            if C == self.myFRE.cert_user[0]:
                self.mirror_control(newNH)
                return
            found = False
            for j, x in enumerate(self.MRM[C].node_list):
                if x[0] == newNH:
                    self.MRM[C].node_list[j][1] = "ACK_PENDING"
                    found = True
                    break
            if not found:
                self.MRM[C].node_list.append([newNH, "ACK_PENDING"])
            #t = threading.Timer(self.ack_time, timer, args=(self.main_mng, C, newNH, "ACK_PENDING"))
            #t.start()
            key = self.NUid[newNH]
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCR", self.MRM[C].pcr, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
            self.logger.info("Sending: {0} "
                        "------ {1} -> {2}, C: {3}, TTL: {4}".format("S_MAT_PCR", self.myFRE.name[0], self.FRT[key].name[0], 
                                                                        binascii.hexlify(C[:3]), binascii.hexlify(
                                                                        self.MRM[C].pcr[1][::65]))) 

    def receivedMAY(self, item):
        if item.fromNid not in self.NUid:
            return
        key = self.NUid[item.fromNid]
        if key not in self.FRT or self.FRT[key].status == "FRIENDSHIP_RECEIVED":
            self.logger.info("receivedMAY: UNKNOWN FRIEND!")
            return
        Nid = None
        for i, x in enumerate(self.MRM[item.data].node_list):
            if x[0] == item.fromNid and x[1] == "ACK_PENDING":
                self.MRM[item.data].node_list[i][1] = "RES_PENDING"
                Nid = x[0]
                break
        if Nid is None:
            self.logger.info("receivedMAY: STATUS NOT CHANGED")
            return
        #t = threading.Timer(self.res_time, timer, args=(self.main_mng, item.data, Nid, "RES_PENDING"))
        #t.start()

    def receivedPEC(self, item):
	    #matCore is the core i successfully registered (I am an entrypoint for this core)
        matCore=item.data
        if matCore not in self.MRM:
            #print "discarding dhtLkKey "+str(item.data.encode('hex'))
            return
        #Nid is the inner hop in the chain that leads me to the core
        Nid = self.MRM[matCore].Nid_inh
        if Nid == None:
            print "ERROR--------------UNABLE TO GET THE INNER HOP NODE ID for core "+str(matCore.encode('hex'))
            self.logger.info("receivedPEC MRM key:"+str(matCore.encode('hex'))+" Nid equal None")
            return
        if Nid not in self.NUid:
            print "ERROR--------------INNER HOP IS NOT ONE OF MY FRIENDS!!"
            return
        key = self.NUid[Nid]
        if key not in self.FRT:
            print "ERROR---------------INNER HOP IS NOT ONE OF MY FRIENDS!"
            return
        print "Creating PCC("+str(item.data.encode('hex'))[:4]+") and forwarding it to "+str(key.encode('hex'))[:4]
        self.logger.debug("key - pec:"+str(key))
        self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_PCC", item.data, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
        self.logger.info("Sending: {0}(1) "
                     "------ {2} -> {3}".format("S_MAT_PCC",str(matCore.encode('hex'))[:4], self.myFRE.name[0], self.FRT[key].name[0]))
        
    def sendFIP(self):
        self.load_data()
        nodes = [val.cert_node[0] for val in self.FRT.values()]
        item=MatMessage(None, "R_P2P_FIP", nodes, None, None)
        #item.myIP=(myPubaddr[0],myPubaddr[1],myPubaddr[2])
        self.main_mng.add(item)
        self.logger.info("FIP sent : R_P2P_FIP")
 
        
    def receivedFIP(self, item):
        print "received FIP from "+str(item.data[1])
        if len(item.data[1])!=3:
            print item.data
            print 'Invalid IP format'
            return
        if item.data[0] not in self.NUid:
            print "FIP error - nid "+ item.data[0] +" not in NUid"
            return
        key = self.NUid[item.data[0]]
        if key not in self.FRT or self.FRT[key].status == "FRIENDSHIP_RECEIVED":
            print "FIP error - nid "+ item.data[0] +" not in FRT or status=FR"
            return
        self.lock_data.acquire()
        self.FRT[key].ip_addr = item.data[1]
        self.lock_data.release()
        self.sendMHR(self.FRT[key])
    
    def save_CTA(self, nid, cta):
        if nid in self.cta_box:
            self.cta_box[nid] += cta
        else:
            self.cta_box[nid] = [cta]
            
    def get_CTA(self, nid):
        if nid not in self.cta_box:
            return None
        else:
            list = self.cta_box[nid]
        del self.cta_box[nid]
        
        return list
    
   
    def receivedCTA(self, item):
        CTA = item.data
        C, friendToken = CTA
        
        #if the core node is in my MRM
        if C not in self.MRM:
            self.logger.info("receivedCTA: INVALID MATRYOSHKA")
            return
        
        #if I'm not entrypoint for C
        if self.MRM[C].node_list != []:
            if item.fromNid not in self.NUid:
                return
            key = self.NUid[item.fromNid]
            #if the sender is not one of my friend
            if key not in self.FRT or self.FRT[key].status == "FRIENDSHIP_RECEIVED":
                self.logger.info("receivedCTA: UNKNOWN FRIEND!")
                return
            
        #if C is one of my friend    
        if C in self.FRT:
            #if I'm mirror of C
            if self.MRM[C].Nid_inh == self.FRT[C].cert_node[0]:
                print 'receivedCTA: I am a mirror of C: '+str(C.encode('hex'))
                if self.FRT[C].online == True:
                    self.logger.debug("receivedCTA: I'm a mirror of C :"+str(C.encode('hex'))+" and C is online") 
                    self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_CTA", CTA, self.FRT[C].ip_addr, self.FRT[C].cert_node[1]))
                else:
                    self.logger.debug("receivedCTA: I'm a mirror of C :"+str(C.encode('hex'))+" and C is offline, store CTA") 
                    self.save_CTA(self.FRT[C].cert_node[0],CTA)
                    #self.usr_mng.dbm.addToFAT(binascii.hexlify(self.FRT[key].cert_node[0]), item.data)
                return
            
        #if I'm C
        if C == self.myFRE.cert_user[0]:
            decrypted = pickle.loads(crypto.decrypt(crypto.loadKeyPair(self.myFRE.cert_user[0].encode('hex')+'_U_'), friendToken))
            if decrypted[0]=='BadgeRequest':
                print 'BA recieved'
                if len(decrypted)!=4:
                    print 'Invalid data: Cannot add the key request, seem tampered...'
                    return
                msg,senderCert,listofkeys,signatures=decrypted
                if senderCert[0] not in self.FRT.keys():
                    print 'Rejected bagde request: Not my friend...'
                    return
                #verify signatures               
                uidSender=binascii.hexlify(senderCert[0])  
                print 'Recieved New keys from uid = '+uidSender
                self.FRT[senderCert[0]].listofkeys.extend(listofkeys) 
                for key in listofkeys:
                    self.usr_mng.dbm.addDKR(key[1],key[0])
                    self.usr_mng.dbm.addUpdateFDD(uidSender,key[0])
                return
            else:
                data = decrypted[:len(decrypted)-4]
                pkey=data[1][1]
                if functions.verifyPropertiesList(data[2:len(data)-1], pkey[1], data[len(data)-1]):
                #if functions.verifyPropertiesList(data[:len(data)-1], crypto.loadPublicKey(data[0][0].encode('hex')+"_U_"), data[len(data)-1]):
                    self.logger.info("receivedCTA: received data are valid")
                    #saving userID public key
                    f=open("mypem"+os.sep+data[1][0].encode('hex')+"_U_PKey.pem","wb")
                    f.write(str(pkey))
                    f.close()
                else:
                    self.logger.info('receivedCTA: received data are not valid')
                        
                #generating result for the UI
                result = []
                data = data[1:len(data)-1]   #remove signature
                for datum in data:
                    result.append(datum[0])
                
                if result[0] not in self.FRT.keys():                        #received a new friendship request
                    
                    result.append(decrypted[len(decrypted)-1])
                    self.usr_mng.addFriendshipRequest(result)
                    cert_user = decrypted[len(decrypted)-4]
                    cert_node = decrypted[len(decrypted)-3]
                    listofkeys = decrypted[len(decrypted)-2]#@Ali
                    self.logger.info("Received Friendship Request from user:\n\tName: "+str(result[1])+" Surname: "+str(result[2])+"\n\tUid: "+str(result[0])+"\n\tNid: "+str(binascii.hexlify(cert_node[0])))
                    lookUpData = (result[1], result[2] , result[4].split('/')[2], result[5], result[6])
                    self.lock_data.acquire()
                    self.FRT[binascii.unhexlify(result[0])] = FRE(lookUpData, cert_user, cert_node, None, False, '', None, "FRIENDSHIP_RECEIVED",listofkeys)
    #                self.FAC[binascii.unhexlify(result[0]).encode('hex')]=listofkeys #@Ali give reference for userr manager to get keys for decryption
                    #@Ali writting to database
                    for key in listofkeys:
                        self.usr_mng.dbm.addDKR(key[1],key[0])
                        self.usr_mng.dbm.addUpdateFDD(result[0],key[0])
                    #
     #TONY check if it has to be unexilified              
    #                self.NUid[cert_node[0]]=result[0]
                    self.lock_data.release()
                    print "Initializing NUId of node %s corresponding to user %s" % (result[0], binascii.hexlify(cert_node[0]))
                    self.NUid[cert_node[0]]=binascii.unhexlify(result[0])
                    self.printFRT()
    
                elif self.FRT[result[0]].status == "FRIENDSHIP_SENT":   #received a friendship response
                    self.lock_data.acquire()
                    cert_node = decrypted[len(decrypted)-3]
                    listofkeys = decrypted[len(decrypted)-2]#@Ali
                    self.FRT[result[0]].cert_node=cert_node
                    self.FRT[result[0]].status = "FRIENDSHIP_ESTABLISHED"
                    self.FRT[result[0]].listofkeys=listofkeys#@Ali
    #                self.FAC[result[0].encode('hex')]=listofkeys #@Ali give reference for userr manager to get keys for decryption
                    #@Ali writting to database
                    #@Ali writting to database
                    for key in listofkeys:
                        self.usr_mng.dbm.addDKR(key[1],key[0])
                        self.usr_mng.dbm.addUpdateFDD(binascii.hexlify(result[0]),key[0])
                            
                    #
                    # this line is redundant (alread done at the very first sendFRA)
                    #print "# NUId Initialized (2)"
                    #self.NUid[cert_node[0]]=result[0]
                    self.lock_data.release()
                    print "receivedCTA: FRIENDSHIP_ESTABLISHED - Friend: "+str(self.FRT[result[0]].name[0])
                     
                    print "Initializing NUId of node" + binascii.hexlify(cert_node[0])
                    self.NUid[cert_node[0]]=result[0]
                    print "sending FIP request for node" + binascii.hexlify(cert_node[0])
                    self.main_mng.add(MatMessage(None, "R_P2P_FIP", [cert_node[0]], None, None))
                    self.logger.info("FIP sent : R_P2P_FIP") 
            
                                   
    #TONY
                    #self.sendSpecificFIP([self.FRT[result[0]].cert_node[0]])
                    #self.sendMHR(self.FRT[result[0]])
                    #self.mirror_control(cert_node[0])
                elif self.FRT[result[0]].status == "FRIENDSHIP_ESTABLISHED":
                     self.logger.info("Received a friendship request from a person who is already a friend!")
                elif self.FRT[result[0]].status == "FRIENDSHIP_RECEIVED":
                     self.logger.info("receivedCTA: Received a friendship request from a person who already sent one before!")
                
                return
        
        #if I'm not a mirror of C nor C, forward CTA
        ph = self.MRM[C].Nid_inh
        self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_CTA", CTA, self.FRT[self.NUid[ph]].ip_addr, self.FRT[self.NUid[ph]].cert_node[1]))
        self.logger.debug("ReceivedCTA: forward CTA to:"+str(ph.encode('hex')))
        
    def receivedCAD(self, item):
        CAD = item.data
        if item.fromNid not in self.NUid:
            return
        key = self.NUid[item.fromNid]
        if key not in self.FRT or self.FRT[key].status == "FRIENDSHIP_RECEIVED":
            self.logger.info("receivedCAD: CAD DENIED!")
            return
        
        self.forwardCA(CAD)
        
    def forwardCA(self, CAD):
        global delegate_threshold
        rnd = random.random()
        #modifued by andrea
        #if rnd < delegate_threshold:
        if "1"=="2":
            #select a mirror
            random_m = random.randint(0, len(self.MRM[self.myFRE.cert_user[0]].node_list)-1)
            nid = self.MRM[self.myFRE.cert_user[0]].node_list[random_m]
            key = self.NUid[nid]
            self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_CAD", CAD, self.FRT[key].ip_addr, self.FRT[key].cert_node[1]))
        else:
            uid, epl, friendToken = CAD
            CTA = (uid, friendToken)
            for x in epl:
                self.main_mng.add(MatMessage(self.myFRE.cert_node[0], "S_MAT_CTA", CTA, x.ip_addr, x.cert_node[1]))
                self.logger.info("forwarded: {0} "
                              "------ {1} -> {2}".format("S_MAT_CTA", self.myFRE.name[0], x.ip_addr))
            
    def sendBA(self,userIdReceiver, pKeyOfTheReceiver, entryPointList, cert_user, cert_node,listOfKeys):
        if self.myFRE.cert_user[0] not in self.MRM:
            self.logger.error("sendFRA: I don't have any Matryoshka, I cannot send FRA")
            return
        
        certUid = self.cert_dhtlkeys[len(self.cert_dhtlkeys)-1]
        certNid = self.myFRE.cert_node
        myPrivateKey=open("mypem"+os.sep+ certUid[0].encode('hex')+"_U_Keys.pem").read()
        signatures = crypto.sign(self.keys, (pickle.dumps([certUid[0],certUid]+listOfKeys, pickle.HIGHEST_PROTOCOL)))
        friendToken =['BadgeRequest',certUid, listOfKeys,signatures]
        friendToken = crypto.encrypt(pKeyOfTheReceiver, pickle.dumps(friendToken))
        CAD = (binascii.unhexlify(userIdReceiver), entryPointList, friendToken)
        self.logger.info( 'forwarding BA request')
        self.forwardCA(CAD)
    
    def sendFRA(self, userIdReceiver, txtMsg, pKeyOfTheReceiver, entryPointList, cert_user, cert_node, lookUpData, status,listOfKeys):
        '''generate contact advertisement delegate and send it to a mirror.'''
        #propertyList = self.cert_dhtlkeys[:len(self.cert_dhtlkeys)-1] 
        if self.myFRE.cert_user[0] not in self.MRM:
            self.logger.error("sendFRA: I don't have any Matryoshka, I cannot send FRA")
            return
        
        certUid = self.cert_dhtlkeys[len(self.cert_dhtlkeys)-1]
        certNid = self.myFRE.cert_node
        
        #advTuple = (propertyList, certUid, certNid, txtMsg)
        #signedAdvTuple = (advTuple, crypto.sign(self.keys, pickle.dumps(advTuple, 2)))
        
#        signedAdvTuple = self.FDR[binascii.hexlify(certUid[0])][0].es_dtok
        signedAdvTuple=[]
        signedAdvTuple.extend(self.usr_mng.getFDR(binascii.hexlify(certUid[0]),1)[0][4][3])
#        listOfKeys = {'1':self.badges['1']} # @ali use can set the access keys selecting a specified group(s)
        friendToken = signedAdvTuple + [certUid, certNid, listOfKeys, txtMsg]
        friendToken = crypto.encrypt(pKeyOfTheReceiver, pickle.dumps(friendToken))
        CAD = (binascii.unhexlify(userIdReceiver), entryPointList, friendToken)
        self.forwardCA(CAD)
        self.lock_data.acquire()
        #generate a FRE and append it to FRT
        if status == "1":
  #TONY
            if cert_user[0] in self.FRT.keys() and self.FRT[cert_user[0]].status == "FRIENDSHIP_ESTABLISHED":
                pass
            elif cert_user[0] in self.FRT.keys() and self.FRT[cert_user[0]].status == "FRIENDSHIP_RECEIVED":
                self.FRT[cert_user[0]].status == "FRIENDSHIP_ESTABLISHED"
                #TONY
                print "received->established, sending FIP request for " + binascii.hexlify(self.FRT[cert_user[0]].cert_node[0])
                self.main_mng.add(MatMessage(None, "R_P2P_FIP", [self.FRT[cert_user[0]].cert_node[0]], None, None))
                self.logger.info("FIP sent : R_P2P_FIP") 
            else:
                self.logger.info( "Inserting new entry in FRT for uid: " + binascii.hexlify(cert_user[0]))
                self.FRT[cert_user[0]] = FRE(lookUpData, cert_user, cert_node, None, False, None, None, "FRIENDSHIP_SENT",[])
                self.printFRT()
               
        elif status == "2":
            #self.FRT[cert_user[0]] = FRE(lookUpData, cert_user, cert_node, None, False, None, None, "FRIENDSHIP_ESTABLISHED")
            self.FRT[cert_user[0]].status = "FRIENDSHIP_ESTABLISHED"
        self.FET[cert_user[0]] = entryPointList
        self.lock_data.release()
        
        return
    
    def sendBOR(self,certUidReceiver,certNidReceiver,ipAddrReceiver,propList):
        """
            Send Bootstrap Request, to a core node provided by TIS ( uid,cert_u, nid, cert_n)
            by a new comers (a node without friends on MatchUpBox)
            to a core node
            
            the message is a direct message between two nodes.
            The answer is a BOC (Bootstrap Confirmation).
            input:
                certUidReceiver = (uid, u_p, S_tis(uid+u_p))
                certNidReceiver = (nid, n_p, S_tis(nid+n_p))
                ipAddrReceiver = ip address of the receiver (core node)
                propertyList = [ property, cert_property]
                    cert_property = (h(property),usp,S_tis_s)
            
            Composition(The same as FRA):
            BOR = [ user, friendToken ]
            user = my uid
            friendToken = E_urp(pickle([propertyList,cert_uid,cert_nid,txtmsg,list(K)],S_uss))
            propertyList = [ property, cert_property]
            cert_property = (h(property),usp,S_tis_s)
            
            Legend:
                urp = uid receiver public key
                uss = uid sender private key
                usp = uid sender public key
        """
        #getting my user id certificate (uid, u_p, tis_sign)
        certUidSender = self.myFRE.cert_user
        if not functions.checkCertificate(certUidSender):
            self.logger.error("function: sendBOR - invalid userIdSender certificate length")
            return
        uidSender = certUidSender[0]
        u_pSender = certUidSender[1]
        
        #getting my user private key
        u_sSender = self.keys
        
        #getting my node id certificate (nid, n_u, tis_sign)
        certNidSender = self.myFRE.cert_node
        if not functions.checkCertificate(certNidSender):
            self.logger.error("function: sendBOR - invalid nodeIdSender certificate length")
            return
        nidSender = certNidSender[0]
        n_pSender = certNidSender[1]
        
        #verify my property list correctness
        if not functions.bor_verifyPropertiesList(propList, u_pSender):
            self.logger.error("function: sendBor - invalid property list")
            return
        
        #verify userId Receiver Certificate
        if not functions.checkCertificate(certUidReceiver):
            self.logger.error("function: sendBor - invalid userIdReceiver Certificate")
            return
        #get uid receiver, receiver user public key
        uidReceiver = certUidReceiver[0]
        u_pReceiver = certUidReceiver[1]
        
        if self.FRT.has_key(uidReceiver):
            self.logger.error("function: sendBOR - invalid receiver, is already in my FRT")
            return
        #verify nodeId Receiver Certificate
        if not functions.checkCertificate(certNidReceiver):
            self.logger.error("function: sendBor - invalid nodeReceiver Certificate")
            return
        nidReceiver = certNidReceiver[0]
        n_pReceiver = certNidReceiver[1]
        
        #creating friendToken
        #friendToken = E_urp(pickle([propertyList,cert_uid,cert_nid,txtmsg,list(K)],S_uss))
        #friendToken = [propList,certUidSender,certNidSender,"Bootstrap Me",None]
        #print self.badges
       
        #@Ali
        listofkets=[self.usr_mng.getKey('Friends')]
        self.usr_mng.dbm.addACP(binascii.hexlify(uidReceiver),self.usr_mng.dbm.getBID('Public'))
        self.usr_mng.dbm.addACP(binascii.hexlify(uidReceiver),self.usr_mng.dbm.getBID('Friends'))
        #
        friendToken = [propList,certUidSender,certNidSender,"Bootstrap Me",listofkets]#@Ali
        friendToken_p = pickle.dumps(friendToken,protocol=pickle.HIGHEST_PROTOCOL)
        #compute signature under my user private key
        sign = crypto.sign(u_sSender,friendToken_p)
        #append signature in a tuple (friendToken, signature)
        friendToken_signed = (friendToken_p,sign)
        #pickle the data
        friendToken_signed_pickled = pickle.dumps(friendToken_signed, protocol=pickle.HIGHEST_PROTOCOL)
        #encrypt data
        friendToken_signed_pickled_encrypted = crypto.encrypt(u_pReceiver, friendToken_signed_pickled)
        
        #Bor = [my userId, friendToken]
        BOR = [uidSender,friendToken_signed_pickled_encrypted]
        
        self.logger.debug("Sending BOR Request to user:Uid: "+str(uidReceiver.encode('hex'))+"\n\tNid: "+str(nidReceiver.encode('hex')))
        
        #setting the status in BOR_SENT
        self.lock_data.acquire()
        self.FRT[uidReceiver] = FRE([], certUidReceiver, certNidReceiver, None, False, ipAddrReceiver , None, "BOR_SENT",[])#@Ali list of keys empty for this node
        self.lock_data.release()
        #send the message to the receiver ip, encrypted under the node public key of the receiver
        borItem=MatMessage(nidSender, "S_MAT_BOR", BOR, ipAddrReceiver , n_pReceiver)
        borItem.myIP=self.myIP
        self.main_mng.add(borItem)
        print "Sendig Bootstrap Request to uid:"+str(uidReceiver.encode('hex'))
        
    def receivedBOC(self,item):
        """
            Received BOC (Bootstrap Confirmation) 
            by a core node
            the message is a direct message between two nodes.
            
            Composition(The same as FRA):
            BR = [ user, friendToken ]
            user = sender uid
            friendToken = E_urp(pickle([propertyList,cert_uid,cert_nid,txtmsg,list(K)],S_uss))
            propertyList = [ property, cert_property]
            cert_property = (h(property),usp,S_tis_s)
            
            Legend:
                urp = uid receiver public key
                uss = uid sender private key
                usp = uid sender public key
        """
        BOC = item.data
        if len(BOC) != 2:
            self.logger.error("Invalid BOC len")
            return
        
        uidSender, friendToken = BOC
        
        #i'm the receiver, so UsedID private key = my user id private key
        u_sReceiver = self.keys
        
        # decrypt friendtoke under my user private key and unpickle
        try:
            friendToken_clear_unpickle =pickle.loads(crypto.decrypt(u_sReceiver, friendToken))
        except:
            self.logger.error("Invalid BOC decryption")
            return
        
        if len(friendToken_clear_unpickle)!=2:
            self.logger.error("Invalid BOC friendToken len")
            return
        
        data_p,signature=friendToken_clear_unpickle
        data = pickle.loads(data_p)
        
        #verify data len
        if len(data)!=5:
            self.logger.error("invalid data in BOC")
            return
            
        propList_all,certUidSender,certNidSender,msg,listK=data
        propList=propList_all[1:]
        #veify uid certificate
        if not functions.checkCertificate(certUidSender):
             self.logger.error("Invalid user certificate in BOC")
             return
        
        #verify nid certificate
        if not functions.checkCertificate(certNidSender):
             self.logger.error("Invalid node certificate in BOC")
             return
        nidSender = certNidSender[0]
        n_pSender = certNidSender[1]
        
        #get the user public key from the user certificate
        if uidSender != certUidSender[0]:
            self.logger.error("Invalid UserID in BOC (no match)")
            return
        
        #getting sender user id public key from the verified certificate
        u_pSender = certUidSender[1]
        
        #verify friendToken signature according to the user public key
        if not crypto.verify_sign(u_pSender,data_p, signature):
            self.logger.error("Invalid friendToken signature on BOC")
            return
        
        #verify property list according to the user public key 
        if not functions.bor_verifyPropertiesList(propList, u_pSender):
            self.logger.error("Invalid property list in BOC")
            return
        
        if uidSender in self.FRT.keys() and self.FRT[uidSender].status == "BOR_SENT":
            #received a BOR from unknown user
            self.logger.debug("Received BOC Friendship Confirmation from user:\n\tName: "+str(propList[0][0])+" Surname: "+str(propList[1][0])+"\n\tUid: "+str(uidSender.encode('hex'))+"\n\tNid: "+str(nidSender.encode('hex')))
            print "Received Bootstrap Confirmation from uid:"+str(uidSender.encode('hex'))+" name:"+str(propList[0][0])+" surname:"+str(propList[1][0])
            #creating lookupdata from propertylist
            lookUpData = (propList[0][0], propList[1][0] , propList[3][0].split('/')[2], propList[4][0], propList[5][0])
            #adding sender to table with status BOR_RECEIVED
            self.lock_data.acquire()
            self.FRT[uidSender] = FRE(lookUpData, certUidSender, certNidSender, None, True, item.fromip, None, "FRIENDSHIP_ESTABLISHED",listK)
            #print "i am in recieveBOC"
            #print listK
#            self.FAC[uidSender.encode('hex')]=listK
            #@Ali writting to database
            for key in listK:
                self.usr_mng.dbm.addDKR(key[1],key[0])
                self.usr_mng.dbm.addUpdateFDD(uidSender.encode('hex'),key[0])       
            #
            #self._save_objects()
            #self._load_objects()
            #self.NUid[nidSender.encode('hex')]= uidSender
            self.NUid[self.FRT[uidSender].cert_node[0]]= uidSender
            self.lock_data.release()
            self.usr_mng.dbm.addUpdatePPI(uidSender.encode('hex'), propList[0][0], propList[1][0], propList[2][0], propList[3][0], propList[4][0], propList[5][0], propList[6][0],   propList[7][0] ,     propList[8][0],         propList[9][0],     propList[10][0],         propList[11][0],       propList[12][0],        propList[13][0],          propList[14][0],propList[15][0])
            self.sendFIP()
#            self.sendMHR(self.FRT[uidSender])
            self.mirror_control(nidSender)
        else:
            self.logger.debug("Received BOC from an incorrect user")
            return

    def receivedBOR(self,item):
        """
            Received BOR (Bootstrap Request) 
            by a new comers (a node without friends on MatchUpBox)
            the message is a direct message between two nodes.
            The answer is a BC (Bootstrap Confirmation).
            
            Composition(The same as FRA):
            BR = [ user, friendToken ]
            user = sender uid
            friendToken = E_urp(pickle([propertyList,cert_uid,cert_nid,txtmsg,list(K)],S_uss))
            propertyList = [ property, cert_property]
            cert_property = (h(property),usp,S_tis_s)
            
            Legend:
                urp = uid receiver public key
                uss = uid sender private key
                usp = uid sender public key
        """
        BOR = item.data
        if len(BOR) != 2:
            self.logger.error("Invalid BOR len")
            return
        
        uidSender, friendToken = BOR
        
        #i'm the receiver, so UsedID private key = my user id private key
        u_sReceiver = self.keys
        
        # decrypt friendtoke under my user private key and unpickle
        try:
            friendToken_clear_unpickle =pickle.loads(crypto.decrypt(u_sReceiver, friendToken))
        except:
            self.logger.error("Invalid BOR decryption")
            return
        
        if len(friendToken_clear_unpickle)!=2:
            self.logger.error("Invalid BOR friendToken len")
            return
        
        data_p,signature=friendToken_clear_unpickle
        data = pickle.loads(data_p)
        
        #verify data len
        if len(data)!=5:
            self.logger.error("invalid data in BOR")
            return
            
        propList,certUidSender,certNidSender,msg,listK=data
        
        #verify uid certificate
        if not functions.checkCertificate(certUidSender):
             self.logger.error("Invalid user certificate in BOR")
             return
        
        #verify nid certificate
        if not functions.checkCertificate(certNidSender):
             self.logger.error("Invalid node certificate in BR")
             return
        nidSender = certNidSender[0]
        n_pSender = certNidSender[1]
        
        #get the user public key from the user certificate
        if uidSender != certUidSender[0]:
            self.logger.error("Invalid UserID in BOR (no match)")
            return
        
        #getting sender user id public key from the verified certificate
        u_pSender = certUidSender[1]
        
        #verify friendToken signature according to the user public key
        if not crypto.verify_sign(u_pSender,data_p, signature):
            self.logger.error("Invalid friendToken signature on BOR")
            return
        
        #verify property list according to the user public key 
        if not functions.bor_verifyPropertiesList(propList, u_pSender):
            self.logger.error("Invalid property list in BOR")
#            print propList
            return
        
        if uidSender not in self.FRT.keys():
            #received a BOR from unknown user
            self.logger.debug("Received BOR Friendship Request from user:\n\tName: "+str(propList[0][0])+" Surname: "+str(propList[1][0])+"\n\tUid: "+str(uidSender.encode('hex'))+"\n\tNid: "+str(nidSender.encode('hex')))
            #creating lookupdata from propertylist
            lookUpData = (propList[0][0], propList[1][0] , propList[3][0].split('/')[2], propList[4][0], propList[5][0])
            #adding sender to table with status BOR_RECEIVED
            self.lock_data.acquire()
            self.FRT[uidSender] = FRE(lookUpData, certUidSender, certNidSender, None, True, item.fromip , None, "BOR_RECEIVED",listK)#@Ali keys added
#            self.FAC[uidSender.encode('hex')]=listK#@Ali
            #@Ali writting to database
            for key in listK:
                self.usr_mng.dbm.addDKR(key[1],key[0])
                self.usr_mng.dbm.addUpdateFDD(uidSender.encode('hex'),key[0])         
            #
            self.lock_data.release()
            #self.usr_mng.dbm.addUpdatePPI(self,functions.getUid(), propList[0][0], propList[1][0], propList[2][0], propList[3][0], propList[4][0], propList[5][0], '' ,'','','', '', '', '', '','')
            certUidReceiver = self.myFRE.cert_user
            uidReceiver = certUidReceiver[0]
            #computing propList from my table CACCIAVITE!!!!
#            signedAdvTuple = self.FDR[uidReceiver.encode('hex')][0].es_dtok
            signedAdvTuple=[]
            signedAdvTuple.extend(self.usr_mng.getFDR(uidReceiver.encode('hex'),1)[0][4][3][1:18])
#            print signedAdvTuple[0][0]
#            print signedAdvTuple[1][0]
#            signedAdvTuple.extend(self.usr_mng.dbm.retrieveAllColumns('PPI',uidReceiver.encode('hex')))
#            propListReceiver=signedAdvTuple[1:]
            propListReceiver=signedAdvTuple[0:]
            
            #getting the ip address of the sender
            nodes = [nidSender]
            #self.main_mng.add(MatMessage(None, "R_P2P_FIP", nodes, None, None))
            ipAddrSender=item.fromip

            #sending BOC @Ali BOC should send his keys for decyption
            self.sendBOC(certUidSender,certNidSender,ipAddrSender,propListReceiver)
            #import Managers
            self.usr_mng.dbm.addUpdatePPI(str(uidSender.encode('hex')), propList[0][0], propList[1][0], propList[2][0], propList[3][0], propList[4][0], propList[5][0], propList[6][0],   propList[7][0] ,     propList[8][0],         propList[9][0],     propList[10][0],         propList[11][0],       propList[12][0],        propList[13][0],          propList[14][0],(propList[15][0]))
        else:
            self.logger.debug("Received BOR from an already known user")
            return
                
    
    def sendBOC(self,certUidReceiver,certNidReceiver,ipAddrReceiver,propList):
        """
            Send Bootstrap Confirmation, to a new comers who sent us a BOR
            from a core node
            to the new comer (a node without friends on MatchUpBox)
            
            the message is a direct message between two nodes.
            
            input:
                certUidReceiver = (uid, u_p, S_tis(uid+u_p))
                certNidReceiver = (nid, n_p, S_tis(nid+n_p))
                ipAddrReceiver = ip address of the receiver (core node)
                propertyList = [ property, cert_property]
                    cert_property = (h(property),usp,S_tis_s)

            Composition(The same as FRA):
            BOC = [ user, friendToken ]
            user = my uid
            friendToken = E_urp(pickle([propertyList,cert_uid,cert_nid,txtmsg,list(K)],S_uss))
            propertyList = [ property, cert_property]
            cert_property = (h(property),usp,S_tis_s)
            Legend:
                urp = uid receiver public key
                uss = uid sender private key
                usp = uid sender public key
        """
        #getting my user id certificate (uid, u_p, tis_sign)
        certUidSender = self.myFRE.cert_user
        if not functions.checkCertificate(certUidSender):
            self.logger.error("function: sendBOC - invalid userIdSender certificate length")
            print "function: sendBOC - invalid userIdSender certificate length"
            return
        uidSender = certUidSender[0]
        u_pSender = certUidSender[1]
        
        #getting my user private key
        u_sSender = self.keys
        
        #getting my node id certificate (nid, n_u, tis_sign)
        certNidSender = self.myFRE.cert_node
        if not functions.checkCertificate(certNidSender):
            self.logger.error("function: sendBOC - invalid nodeIdSender certificate length")
            print "function: sendBOC - invalid nodeIdSender certificate length"
            return
        nidSender = certNidSender[0]
        n_pSender = certNidSender[1]
        
        #verify my property list correctness
        if not functions.bor_verifyPropertiesList(propList[1:], u_pSender):
            self.logger.error("function: sendBOC - invalid property list")
            print "function: sendBOC - invalid property list"
#            print propList[0]
            return
        
        #verify userId Receiver Certificate
        if not functions.checkCertificate(certUidReceiver):
            self.logger.error("function: sendBOC - invalid userIdReceiver Certificate")
            print "function: sendBOC - invalid userIdReceiver Certificate"
            return
        #get uid receiver, receiver user public key
        uidReceiver = certUidReceiver[0]
        u_pReceiver = certUidReceiver[1]
        
        #verify nodeId Receiver Certificate
        if not functions.checkCertificate(certNidReceiver):
            self.logger.error("function: sendBOC - invalid nodeReceiver Certificate")
            print "function: sendBOC - invalid nodeReceiver Certificate"
            return
        nidReceiver = certNidReceiver[0]
        n_pReceiver = certNidReceiver[1]
        
        #check if the user has sent a BOR request
        if self.FRT[uidReceiver].status != "BOR_RECEIVED":
            self.logger.error("function sendBOC - sending BOC to an user that didn't send us a BOR")
            print "function sendBOC - sending BOC to an user that didn't send us a BOR"
            return
        
        #creating friendToken
        #friendToken = E_urp(pickle([propertyList,cert_uid,cert_nid,txtmsg,list(K)],S_uss))
        #friendToken = [propList,certUidSender,certNidSender,"I'm Bootstrappin you",None]
        #@Ali
        listofkets=[self.usr_mng.getKey('Friends')]
        self.usr_mng.dbm.addACP(binascii.hexlify(uidReceiver),self.usr_mng.dbm.getBID('Public'))
        self.usr_mng.dbm.addACP(binascii.hexlify(uidReceiver),self.usr_mng.dbm.getBID('Friends'))
        #
        friendToken = [propList,certUidSender,certNidSender,"I'm Bootstrappin you",listofkets]#@Ali
        
        friendToken_p = pickle.dumps(friendToken, protocol=pickle.HIGHEST_PROTOCOL)
        #compute signature under my user private key
        sign = crypto.sign(u_sSender,friendToken_p)
        #append signature in a tuple (friendToken, signature)
        
        friendToken_signed = (friendToken_p,sign)
        #pickle the data
        friendToken_signed_pickled = pickle.dumps(friendToken_signed, protocol=pickle.HIGHEST_PROTOCOL)
        #encrypt data
        friendToken_signed_pickled_encrypted = crypto.encrypt(u_pReceiver, friendToken_signed_pickled)
        
        #BOC = [my userId, friendToken]
        BOC = [uidSender,friendToken_signed_pickled_encrypted]
        
        self.logger.debug("Sending BOC Confirmation to user:Uid: "+str(uidReceiver.encode('hex'))+"\n\tNid: "+str(nidReceiver.encode('hex')))
        
        #setting the status in FRIENDSHIP_ESTABLISHED
        self.lock_data.acquire()
        self.FRT[uidReceiver].status="FRIENDSHIP_ESTABLISHED"
        self.FRT[uidReceiver].online=True
        self.FRT[uidReceiver].ip_addr=ipAddrReceiver
        self.NUid[self.FRT[uidReceiver].cert_node[0]]= uidReceiver
        self.lock_data.release()
        #send the message to the receiver ip, encrypted under the node public key of the receiver
        bocItem=MatMessage(nidSender, "S_MAT_BOC", BOC, ipAddrReceiver , n_pReceiver)
        bocItem.myIP=self.myIP
        print 'Send BOC Address:'+str(ipAddrReceiver)
        self.main_mng.add(bocItem)

       
    def do_work(self, item):
        if not self.running:
            return
        if isinstance(item, Job):
            self.logger.info("Matryoshka manager is working on: {0.type} ".format(item))
        else:
            #self.logger.info("Matryoshka manager is working on: {0.type} "
            #             "------ {1} -> {2}".format(item, self.FRT[self.NUid[item.fromNid]].name[0],
            #                                        self.myFRE.name[0]))
            pass
          
        try:
            if item.type == "R_MAT_MHR":
                self.receivedMHR(item)
            elif item.type.startswith("R_MAT_RELAYREQUEST"):
                self.relayRequest(item)
            elif item.type.startswith("R_MAT_RELAYRESPONSE"):
                self.relayResponse(item)
            elif item.type == "R_MAT_PRR":
                self.receivedPRR(item)
            elif item.type == "R_MAT_DSR":
                self.receivedDSR(item)
            elif item.type == "R_MAT_PRS":
                self.receivedPRS(item)
            elif item.type == "R_MAT_DSC":
                self.receivedDSC(item)
            elif item.type == "R_MAT_MHC":
                self.receivedMHC(item)
            elif item.type == "R_MAT_MBR":
                self.receivedMBR(item)
            elif item.type == "R_MAT_PCR":
                self.receivedPCR(item)
            elif item.type == "R_MAT_PCC":
                self.receivedPCC(item)
    # TONY
    #        elif item.type == "R_MAT_MTO":
    #            self.receivedMTO(item)
            elif item.type == "R_MAT_MAY":
                self.receivedMAY(item)
            elif item.type == "R_MAT_MAN":
                self.receivedMAN_PCF(item, 'MAN')
            elif item.type == "R_MAT_PCF":
                self.receivedMAN_PCF(item, 'PCF')
            elif item.type == "R_MAT_PEC":
                self.receivedPEC(item)
            elif item.type == "R_MAT_MLI":
                self.receivedMLI()
            elif item.type == "R_MAT_FIP":
                self.receivedFIP(item)
            elif item.type == "R_MAT_DFR":
                self.receivedDFR(item)
            elif item.type == "R_MAT_DFC":
                self.receivedDFC(item)
            elif item.type == "R_MAT_CAD":
                self.receivedCAD(item)
            elif item.type == "R_MAT_CTA":
                self.receivedCTA(item)
            elif item.type == "R_MAT_BOC":
                self.receivedBOC(item)
            elif item.type == "R_MAT_BOR":
                self.receivedBOR(item)
            elif item.type == "R_MAT_PRN":
                self.receivedPRN(item)
                
            else:
                self.logger.info("UNKNOWN TYPE: {0}".format(item.type))
        except:
            print 'Error in MAT Do_WORK.'
            print traceback.print_exc()
            pass       
        
    def close(self):
        logging.info("Shutting down Matryoshka Manager...")
        self.running = False
        self.save_timer.cancel()
        self._save_objects()
        self.save_timer.cancel()
        self.sendMBR()
        self.unregister_as_ep()
        if self.big_brother:
            self.send_big_brother()
            self.big_brother_timer.cancel()
        super(MatryoshkaMng, self).close()
        
