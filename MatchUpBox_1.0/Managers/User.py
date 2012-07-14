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

###yu
import threading
import webbrowser
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from os import curdir, sep
import sys
import logging
import sqlite3
import cPickle as pickle
import urllib
import random
import datetime
import socket
import cStringIO
from twisted.internet import defer
import Managers.Manager as Manager
from Managers.Matryoshka import FEP
from Managers.Matryoshka import DRE
import Managers.Dispatcher
from Messages import Job
from cookielib import debug
import functions
from time import sleep
import binascii
import crypto
import constants
import os
import Image
from email.charset import BASE64
from PIL import Image #@Ali
from time import gmtime, strftime #@Ali
from base64 import b64encode, b64decode #@Ali
import StringIO #@Ali
import cgi
import traceback
import time
from thread_debug_decorator import debug

usrmng=''   # global variable to let the HTTP handler objects know a reference to the User Manager
dispatcher=''
def getRetrivalRateParameters(file_ret_rate):
    if os.path.getsize(file_ret_rate.name)!= 0:
        #overide with new values
        line=file_ret_rate.readline()
        temp=line.strip().split('=')
        retrieval_interval_temp=temp[1]
        line=file_ret_rate.readline()
        temp=line.strip().split('=')
        retrieval_interval_initial_temp=temp[1]
        return (int(retrieval_interval_temp),int(retrieval_interval_initial_temp))
    else:
        return (95,200) # default retrival rate

file_retrivalRate = open('conf'+os.sep+'retrival_rate.dat', 'rb')
ret_parm=getRetrivalRateParameters(file_retrivalRate)
file_retrivalRate.close()
retrieval_interval = ret_parm[0]
retrieval_interval_initial = ret_parm[1]  #wait until the nodes register and kill responsible threads
guid = -1
openpageid = '-1'
searchTime = 20
counter = -1
finished = False
numberOfSearches = -1
retrievedAllSearchData = False
currentSearchResults = {}
advDelegateSent = False
entryPoints, publicKeys, friendshipRequests, certUsers, certNodes = {}, {}, {}, {}, {}
badgesKey={}						# it's a dictionary linking a list of badges to a single symmetric encryption key used to encrypt data for contacts holding ALL these badges
Ulogger=0
AESKLEN=256
IV='\0'* (AESKLEN/8)
class UserMng(Manager.Manager):

    url='http://localhost:8080/profile.html#uid=' + str(functions.getUid()) + '?'
    db_filename = "dbData"+sep+"db%s.db"% str(functions.getUid())       # SQLite3 database path
    def __init__(self, mName, main_mng):
        global guid
        guid = functions.getUid()
        self.myFRE=None
        self.cert_dhtlkeys=None
        global Ulogger
        Ulogger = logging.getLogger("User")        
        fmt = logging.Formatter("%(threadName)-17s - %(asctime)s: - %(message)s")
        handler=logging.FileHandler("log"+os.sep+"User.log","w")
        handler.setFormatter(fmt)
        Ulogger.addHandler(handler)
        Ulogger.setLevel(logging.DEBUG)
        Ulogger
        Manager.Manager.__init__(self, mName, main_mng)
        Ulogger.info("User Manager started...")
        self.dbm = DataManager(self.db_filename)    # create data manager
        self.l = threading.Lock()
        
        global usrmng   # to use usrmng as global variable in this contex, and do not create a local variable having the same name
        usrmng = self
        
        self.server = sbHTTPServer()
        self.server.start()                 # start the web server
        
        self.web_ctrl = webbrowser.get()
        self.web_ctrl.open(self.url, 2, True)    # open the default web browser of the system
        Ulogger.info("Web interface started...")
        
        global dispatcher
        dispatcher = main_mng
        
        #@Ali
        f=open('conf'+os.sep+'badges.dat', 'r')
        for bdgname in f.readlines():
            try:
                name=bdgname.strip()
                if name=='Public':
                    self.generatekeyforBatch(name,batchID=0)
                elif name=='Friends':
                    self.generatekeyforBatch(name,batchID=1)
                else:
                    self.generatekeyforBatch(name)
            except:
                self.dbm.l.release()
                print traceback.print_exc()
        f.close()   
#  
  		#initialize the badgesKey dictionary
        queryString='SELECT KEY_ID FROM DKR'
        try:
            rows=usrmng.dbm.executeQuery(queryString)
        except:
            print "ERROR: unable to get the list of KID from DKR"
            return
        for row in rows:
            query2='SELECT BID FROM BKR WHERE KEY_ID="{0}"'.format(row[0])
            #print query2
            try:
                badges=usrmng.dbm.executeQuery(query2)
                blist=[str(badge[0]) for badge in badges]
                #print "blist: "+str(blist)
                badgesKey[tuple(blist)]=row[0]
                #print badgesKey
            except:
                print "ERROR: unable to get the list of BID from BKR"
                return
        badgesKey[tuple("0")]=0				
        
        #TONY add default association between badge 0 and key 0
        usrmng.dbm.addUpdateBKR(0,0)
        
        global retrieval_interval_initial
        #GINO TIMER
        self.t2=threading.Timer(retrieval_interval_initial, self.getPosts,(0,))  # timer to send the profile retrieval message to Matrioshka Manager
        self.t2.setName('USR_prr_Timer')
        self.t2.start()
      
    def setparameterforusr_mng(self,myfre,dhtkeys,keys):
        self.myFRE=myfre
        self.cert_dhtlkeys=dhtkeys
        self.keys=keys
    #@Ali
    def queryStringPST(self,badgeName):
        if badgeName=='Square':
            return 'SELECT ID FROM PST WHERE ID=FIRSTID ORDER BY TIME DESC'
        bid=self.dbm.getBID(badgeName)
        kid=self.dbm.checkKey(bid)
        acplist=self.dbm.getACPList(bid)
        didlist=self.dbm.getDEK('PST', kid)
        
        if len(acplist)==0 and len(didlist)==0:#No post to show
            return ''
        
        query='SELECT ID FROM PST WHERE '
        if len(didlist)!=0:
            query+="(ID=FIRSTID AND UIDOWNER='"+guid+"' AND ("

            for did in didlist:
                query+=' ID='+str(did[0])+' OR'
            if len(didlist)!=0:
                query=query[0:len(query)-2]
                query+='))'
        if len(acplist)!=0:
            if len(didlist)!=0:
                query+=' OR ( ID=FIRSTID AND ('
            else:
                query+=' ( ID=FIRSTID AND ('
            for uid in acplist:
                query+=" UIDOWNER='"+uid[0]+"' OR"
            query=query[0:len(query)-2]
            query+='))'
        query+=' ORDER BY TIME DESC'
        return query
    #@Ali
    def getFDR(self,uid,did=None):
        #TONY CHECK LOCK
#        print 'getFDR locked'
#        self.l.acquire()
        try:
            rows=self.dbm.getFDRfromDB(uid,did)
        except:
            print 'Error in reading from FDR table'
#            self.l.release()
            return []
        try:
            fdrRow=[]
            for row in rows:
                if len(row)==0:
#                    print 'getFDR unlocked'
#                    self.l.release()
                    return fdrRow
                uid,did,fcount,kid,Fr_ESDT=row[0]
                if kid!=0:
                    key=self.dbm.getkeyDKR(kid)
                    if key!=-1:
                        try:
                            fdrRow.append([uid,did,fcount,kid,pickle.loads(b64decode(crypto.decrypt_AES(Fr_ESDT, key, IV)))])
                        except:
                            print 'Error getFDR: pickle/decrypt error, releasing lock and returning'
                            print traceback.print_exc()
 #                           print 'getFDR unlocked'
  #                          self.l.release()
                            return []
                    else:
                        print 'Key not found'
                else:
                    fdrRow.append([uid,did,fcount,kid,pickle.loads(b64decode(Fr_ESDT))])
    #        print 'getFDR unlocked'
   #         self.l.release()
            return fdrRow
            
        except:
            print 'Error in getFDR'
            print traceback.print_exc()
      #      print 'getFDR unlocked'
     #       self.l.release()
            return []
       # print 'getFDR unlocked'
        #self.l.release()
            
    #@Ali
    def getKey(self,batchName):
        #TONY CHECK LOCK
#        print 'getKey locked'
#        self.l.acquire()
        if batchName=='Public':
   #         print 'getKey unlocked'
   #         self.l.release()
            return (0,'0')
        bid=self.dbm.getBID(batchName)
        #print "BID="+str(bid)
        key=-1
        if bid != -1:
            kid=self.dbm.checkKey(bid)
            #print "KID="+str(kid)
            if kid!=-1:
                key=self.dbm.getkeyDKR(kid)
        else:
            print "badge "+str(batchName)+"was not found in the database"		
		#TONY		
        #if key!=-1:
        #    return (kid,key)
        #else:
        #    print 'DKR: Key not found'
        if key==-1:	
            print "generating new key for badge "+str(batchName)		
            kid=random.randint(1,sys.maxint)
            key=b64encode(crypto.genRandomKey(AESKLEN))
            usrmng.dbm.addUpdateDKR(kid,key)     	
            badgesKey[tuple(str(bid))]=kid
            Ulogger.info("getKey: associating badge "+str(bid)+" with key"+str(kid))
            usrmng.dbm.addUpdateBKR(bid,kid)
#        print 'getKey unlocked'
#        self.l.release()		
        return (kid,key)
		
		
		
		
		
		
    
    #@Ali
    def generatekeyforBatch(self, batchName,batchID=None,keySize=AESKLEN):
        "Generate Basic Symmetric keys for user access control i.e Posts, Pictures... User can add additional keys for other attributes"
        #generate 128 bit random key for post and pictures
        bid=self.dbm.addBDG(batchName,batchID)
        if batchName=='Public':
            return
        else:
            skey=self.dbm.checkKey(bid)
            if skey == -1:
                skey=crypto.genRandomKey(keySize)
            else:
                return #Already exist
            kid=self.dbm.addDKR(skey)
            self.dbm.addBKR(bid, kid)
    #@Ali
    def publishKey(self,kid,bidList):
        print 'Publishing New Key to your Corresponding Friends...'
        query='SELECT UIDOWNER FROM ACP WHERE'
        for bid in bidList:
            query+=' BID='+str(bid)+' OR'
        query=query[0:len(query)-3]
        friendList=self.dbm.executeQuery(query)
        def valueFound(result):
            reg_tok, cert_node, ip_addr,  time_v,isSSL = result[0]
            reg_tok_data = reg_tok[0]
            ret_sign = reg_tok[1]
            cert_dhtlk, a = reg_tok_data
            cert_user, ExpireTime = a
            ret_dhtlk, ret_pkeyk, k_sign  = cert_dhtlk
            ret_Uid, ret_pkeyU, u_sign  = cert_user
            if not crypto.verify_tis_cert(cert_user) or not crypto.verify_tis_cert(cert_node):
                print 'unable to verify user/node certificates'
            else:
                key=self.dbm.getkeyDKR(kid)
                key_list=[(kid,key)]
                dispatcher.mat.sendBA(friend[0], ret_pkeyU, [FEP(cert_node, ip_addr, time_v, ExpireTime,isSSL)], cert_user, cert_node,key_list)
                Ulogger.info("Publish Key: Sending BA for KID = "+str(kid)+" to UID="+friend[0])
                print "Publish Key: Sending BA for KID = "+str(kid)+" to UID="+friend[0]
            return
        def valueNotFound(result):
            print "PublishKey: Recursive find failed"
            return
        df={}
        counter=0
        for friend in friendList:
            uid = binascii.unhexlify(friend[0])       
            print "Looking for the entrypoints of ->"+str(friend[0])
            df[counter] = dispatcher.p2p.recursiveFind2(uid)
            df[counter].addCallback(valueFound)
            df[counter].addErrback(valueNotFound)
            counter+=1
            
    #@Ali
    def generatekey(self,keySize=128):
        #generate 128 bit random key for union of badges
        skey=crypto.genRandomKey(keySize)
        kid=self.dbm.addDKR(skey)
        return kid   
    
#FIXME TONY this function should dynamically populate the left column of the page	
    def addSearchResult(self, result):
        self.l.acquire()
        print 'ADD SEARCH RESULT CALLED'
        global numberOfSearches, retrievedAllSearchData, currentSearchResults, publicKeys
        uid,fcount,es_dtok= result
        uidcert,proplist_enc,signature=es_dtok
        proplist=pickle.loads(b64decode(proplist_enc))
        result = proplist[0:]
        if uid not in publicKeys:
            print 'uid not in public keys'
            self.l.release()
            return
#            return publicKeys[uid]
        if functions.verifyPropertiesList(result[1:], publicKeys[uid], signature):
            print 'received data is valid'
        else:
            print 'received data is not valid'
        resultCleared = []
        for i in range(len(result[1:])):
            resultCleared += [result[i+1][0]]
        resultCleared=[binascii.hexlify(uid)]+ resultCleared
#        resultCleared[len(resultCleared) - 1] = cStringIO.StringIO(sqlite3.Binary(b64decode(resultCleared[len(resultCleared) - 1]))).getvalue()\
# TONY TODO: check if one can lock the insertion on currentsearchresult

        currentSearchResults[uid] = resultCleared

        if numberOfSearches == -1:
            Ulogger.info("addSearchResult: I did not request a PPI data but somebody sent.")
            self.l.release()
            return
        self.l.release()
		# FIXME TONY
		# to retrieve more than a single profile, keep it commented
        #if numberOfSearches >= len(currentSearchResults):
        #    retrievedAllSearchData = True
    
    def addFriendshipRequest(self, data):
        self.l.acquire()
        print 'addFriendshipReq locked'
        global friendshipRequests
        data[0]=binascii.hexlify(data[0])
        friendshipRequests[data[0]] = data
        print 'addFriendshipReq unlocked'
        self.l.release()
        
    def getPosts(self,lastIndex):
        'retrieval of PRR (profile retival request) not only posts of friends periodically'
        val=dispatcher.mat.FRT.values()
        lastIndex=lastIndex%len(val)
        dispatcher.mat.add(Job("R_MAT_PRR", val[lastIndex].cert_user[0]))
        lastIndex+=1
#        for val in dispatcher.mat.FRT.values():
#            dispatcher.mat.add(Job("R_MAT_PRR", val.cert_user[0]))
        #gino timer
        self.t2=threading.Timer(retrieval_interval, self.getPosts,(lastIndex,))  # timer to send the profile retrieval message to Matrioshka Manager
        self.t2.setName('USR_prr_Timer')
        self.t2.start()
        
    def sendProfileTostore(self):
        # send the profile store message to Matrioshka Manager
        #TONY TODO CHECK LOCK
        #print 'sendProfileTostore locked'
        #self.l.acquire()
            
        es_dtok=self.getFDR(guid, 1)
        uidcert = es_dtok[0][4][3][1]
        propList = [1]+es_dtok[0][4][3][2:]
        es_dtok2= [uidcert]+[str(b64encode(pickle.dumps(propList)))] + [crypto.sign(self.keys, (pickle.dumps([uidcert[0],uidcert]+propList, pickle.HIGHEST_PROTOCOL)))]
        fcount=usrmng.dbm.findMaxDEK()+1
        usrmng.dbm.addDEK('1',"PPI",0,fcount,str(b64encode(pickle.dumps(es_dtok2,2))))
        content=['PPI',fcount,0,es_dtok2]
#        if flag==True:
#            usrmng.dbm.addupdateFDR(guid,1,fcount,0,str(b64encode(pickle.dumps(content,2))))
        item = [1,fcount,0,str(b64encode(pickle.dumps(content,2)))]
        job = Job("R_MAT_PRS",item)
        self.main_mng.add(job)
        #print 'sendProfileTostore unlocked'
        #self.l.release()
        
    def requesToMat(self):
        rows = usrmng.dbm.retrieveMany("PPI", functions.getUid())
        for x in rows:
            nome= x[2].split(" ")[0]
            job = Job("R_MAT_PRR",nome)
            self.main_mng.add(job)


    def do_work(self, item):
        # overwritten from Manager, called when a new job arrives in the queue
        Ulogger.info("User Manager is working on: %s" % item)
    def close(self):
               
        self.server.join()
        self.t2.cancel()
        Ulogger.info("Shutting down User Manager...")
        Manager.Manager.close(self)
        
            
class sbHTTPHandler(BaseHTTPRequestHandler): 
    # automatically instantiated once every HTTP request 
    global Ulogger	
    # the corresponding do_SOMETHING method is automatically called depending on the HTTP method of the request
    def log_message(self, format, *args):
        return
    def do_GET(self):
        
        me = self
        def generateInfoBox(textSr):
            fields = ['User ID', 'Name', 'Surname', 'Sex', 'Birthday', 'Birth Place', 'Nationality', 'Mail', 'Phone', 'Mobile', 'Company', 'Department', 'Role', 'Mail', 'Phone', 'Mobile']
            result = ''
            for f, t in zip(fields, textSr):
                result += '%s: %s<br>' %(f, t)
            return result
    
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
        
        global guid
		#TONY ADD
        guid = functions.getUid()

        try:             
            if (self.path.find("CMD")!=-1): # if the HTTP request contains CMD (used to issue special commands from ajax scripts)
                # self.path: /CMD?method=store&key=key&value=value (no more used, just from P2P panel)
                # self.path: /CMD?method=profile
                # self.path: /CMD?method=podium#uid
                
                req={}
                params=self.path.split('?')[1].split('&')
                for p in params:    # put the parameters of the request in a dictionary (e.g. req["method"] = "profile")
                    req[p.split('=')[0]] = urllib.unquote(p.split('=')[1]).replace("+"," ").strip()

                if req["method"]=="profile":
                    # retrieve data of my own profile from db and send it as json object
                    global openpageid
                    if req["id"] == '-1':
                        prid = guid
                    else:
                        prid = req["id"]
                    
                    altStr="None"
                    name = usrmng.dbm.retrieve("PPI", "NAME", prid)
                    surname = usrmng.dbm.retrieve("PPI", "LASTNAME", prid)
                    sex = usrmng.dbm.retrieve("PPI", "SEX", prid)
                    birth = usrmng.dbm.retrieve("PPI", "BIRTHDAY", prid)
                    birthP = usrmng.dbm.retrieve("PPI", "BIRTHPLACE", prid)
                    nationality = usrmng.dbm.retrieve("PPI", "NATIONALITY", prid)
                    mail = usrmng.dbm.retrieve("PPI", "MAIL", prid)
                    if mail=="": mail=altStr
                    phone = usrmng.dbm.retrieve("PPI", "FIXEDTEL", prid)
                    if phone=="": phone=altStr
                    mobile = usrmng.dbm.retrieve("PPI", "MOBILETEL", prid)
                    if mobile=="": mobile=altStr
                    company = usrmng.dbm.retrieve("PPI", "COMPANY", prid)
                    if company=="": company=altStr
                    department = usrmng.dbm.retrieve("PPI", "DEPARTMENT", prid)
                    if department=="": department=altStr
                    role = usrmng.dbm.retrieve("PPI", "ROLE", prid)
                    if role=="": role=altStr
                    companymail = usrmng.dbm.retrieve("PPI", "COMPANYMAIL", prid)
                    if companymail=="": companymail=altStr
                    companytel = usrmng.dbm.retrieve("PPI", "COMPANYTEL", prid)
                    if companytel=="": companytel=altStr
                    companymobiletel = usrmng.dbm.retrieve("PPI", "COMPANYMOBILETEL", prid)
                    if companymobiletel=="": companymobiletel=altStr
           
                    resHTML = "({{\"name\": \"{0}\", \"surname\": \"{1}\", \"sex\": \"{2}\", \"birth\": \"{3}\", \"birthP\": \"{4}\", \"nationality\": \"{5}\", \"mail\": \"{6}\", \"phone\": \"{7}\", \"mobile\": \"{8}\", \"company\": \"{9}\", \"department\": \"{10}\", \"role\": \"{11}\", \"companymail\": \"{12}\", \"companytel\": \"{13}\", \"companymobiletel\": \"{14}\", \"uid\": \"{15}\"}})".format(name, surname, sex, birth, birthP, nationality, mail, phone, mobile, company, department, role, companymail, companytel, companymobiletel, prid)
           
                    self.wfile.write(resHTML)
                    return 

                elif req["method"] == "tweet":
                    content = [0, 10, 0, req["word"], 0, 10, 0, True]
                    item = ["PST", content]
                    dispatcher.mat.add(Job("R_MAT_PRS", item))
                    return
                elif req["method"] == "logout":
                    print "logout"
                    print type(dispatcher)
                    class log_out(threading.Thread):
                       def __init__ (self):
                          threading.Thread.__init__(self)
                       def run(self):
                           print 'inside log_out'
                           dispatcher.close()
                           logging.info("Exiting")
                           fake_t = threading.Timer(0,None)
                           for t in threading.enumerate( ):
                               if t.name!='logout':
                                   if type(t) == type(fake_t):
                                       t.cancel()
                                   elif t != threading.current_thread():
                                        t.join(0)
                               else:
                                   final=t
                           os._exit(0)
                           return
                       
                    logout=log_out()
                    logout.daemon=True
                    logout.name='logout'
                    logout.start()
                elif req["method"] == "retrieve":
                    dispatcher.mat.add(Job("R_MAT_PRR", req["word"].strip().lower()))
                    return
                elif req["method"] == "friendRem":
                    dispatcher.mat.removeFriend(req['ruid'].strip('\n').decode('hex'))
                elif req["method"]=="edit":
                    # after having edited my own profile, store in the database the updated data (also the picture)
                    # and send back the "./nowhere/myavatar.jpg" as src of img of avatar picture
                    # --> this will trigger another HTTP request for the image that (see later) will be taken from database
                    # (and yes, it was the only way I knew to update the picture on-the-fly)
                    
                    list_fields = ["mail","phone","mobile","company","department","role","companymail","companytel","companymobiletel","picture"]
                    all=usrmng.dbm.retrieveAllColumns("PPI", guid)
                    
                    p_list = []
                    p_list.extend(all[1:7])
                    i=0
                    for field in list_fields:
                        if field in req and req[field] != 'undefined' and req[field] != '' and req[field] != 'None':
                            if field != 'picture':
                                p_list.append(req[field])
                            else:
                                f_avatar = open(req[field], 'rb' )
                                binaryObject = b64encode(f_avatar.read())
                                f_avatar.close()
                                p_list.append(binaryObject)
                        else:
                            p_list.append(all[7+i])
                        i=i+1
                        
                    usrmng.dbm.addUpdatePPI(guid, p_list[0],p_list[1],p_list[2],p_list[3],p_list[4],p_list[5],p_list[6],p_list[7],p_list[8],p_list[9],p_list[10],p_list[11],p_list[12],p_list[13],p_list[14],sqlite3.Binary(p_list[15]))
                    
                    es_dtok=usrmng.getFDR(guid, 1)
                    uidcert = es_dtok[0][4][3][1]
                    propList = es_dtok[0][4][3][2:]
                    #es_dtok2= [uidcert]+[str(b64encode(pickle.dumps(propList)))] + [crypto.sign(self.keys, (pickle.dumps([uidcert[0],uidcert]+propList, pickle.HIGHEST_PROTOCOL)))]
                    index=0
                    for prop in p_list:
                        propList[index][0]=prop
                        index+=1
                    signedObject = [1]+[uidcert]+propList+ [crypto.sign(usrmng.keys, pickle.dumps([uidcert[0],uidcert]+propList, pickle.HIGHEST_PROTOCOL))]
                    #es_dtok2= [uidcert]+[str(b64encode(pickle.dumps(propList)))] + [crypto.sign(usrmng.keys, (pickle.dumps([uidcert[0],uidcert]+propList, pickle.HIGHEST_PROTOCOL)))]
                    content=['PPI',1,0,signedObject]
                    usrmng.dbm.addupdateFDR(guid,1,1,0,str(b64encode(pickle.dumps(content,2))))
                    usrmng.sendProfileTostore()
#                    data=[0]
#                    data.extend(p_list)
#                    self.job=Job("R_MAT_PRS",("PPI",data))
#                    usrmng.main_mng.add(self.job)
   
                    msg = '<script language="javascript" type="text/javascript" >function refreshpage() {setTimeout("location.reload(true);",200);} refreshpage()</script> '
                    self.send_response(200)
                    self.end_headers()
                    #self.wfile.write(msg)
                    return        
                
                elif req["method"]=="contacts":
                    # generate and send the HTML to put in the contact page
                    
                    rows = usrmng.dbm.retrieveMany("PPI", guid)  # retrieve all the rows that does not have my id in PPI
                                                                        # (all my friends' data)
                    
                    tot=""
                    for r in rows: # for each friend
                        name_pic = "./nowhere/otherprof_%s.jpg"% r[0]    # another trick to generate a request for the image (see later on) 
                        query1='SELECT CONTENT FROM PST WHERE ISTWEET = 1 AND UID = "{0}" ORDER BY TIME DESC'.format(r[0])                        
                        status = usrmng.dbm.executeQuery(query1)
                        
                        if not status:
                            status="_"
                        else:
                            status=status[0][0]
                        
                        one_contact = ('<li><span class="separator">&nbsp;</span><dl><dt class="dTitle">Avatar:</dt><dd class="avatar">'
                                        '<img src={0} /></dd><dt class="dTitle">Full name:</dt><dd class="name"><a href=\"http://localhost:8080/profile.html#uid={1}?\">{2} {3}</a></dd><dd class="name"><a href=\"http://localhost:8080/profile.html#uid={1}?\">{2} {3}</a></dd><dd class="rem"><a href=\"javascript:friendRem(\''+r[0]+'\')\">remove <img src=\"./img/rf.gif\" /></a></dd><dt class="dTitle">Status:</dt>'
                                        '<dd class="status">{4}</dd><dt class="dTitleP">'
                                        '<a href="gallery.html#uid={1}?">Pictures</a></dt><dd class="iconsP"><a href=""><img src="./img/ph.gif" /></a></dd>'   
                                        '<dt class="dTitleW"><a href="podium.html#uid={5}?">Wall</a></dt><dd class="iconsW"><a href=""><img src="./img/wa.gif" />'
                                        '</a></dd><dt class="dTitleM"><a href="">Mail</a></dt><dd class="iconsM"><a href="">'
                                        '<img src="./img/ma.gif" /></a></dd>  </dl></li>').format(name_pic, r[0], r[1], r[2], status, r[0])
                        tot+=one_contact
                    
                    #resHTML = "({{\"name\": \"{0}\", \"sex\": \"{1}\",\"birth\": \"{2}\"}})".format(name,sex,birth)
                                        
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write("<ul>"+tot+"</ul>")
                    return
                
                elif req["method"]=="fRequest":
                    global friendshipRequests
                    if(len(friendshipRequests) == 0):
                        return
                    tot = '<ul>'
                    for key, value in zip(friendshipRequests.keys(), friendshipRequests.values()):
                        textSr = value[:len(value)-2]
                        tot += "<li>New Friendship Adv.<br><img src=\"./nowhere/friend_" + key + ".jpg\" onmousemove=\"showInfoBox('" + generateInfoBox(textSr) + "', event)\" onmouseout=\"hideInfoBox()\" ><br>"
                        tot += textSr[1] + " says: " + value[len(value)-1]
                        link='FRA.html#userId='+textSr[0]+'?#userName='+textSr[1]+'?#status=2?'
                        
                        fralink="<a class=\"fFriend\" id=\"execute\" href=\"#\" onclick=\"window.showModalDialog('"+link+"',null,'dialogWidth:500px;dialogHeight:250px;center:1;scroll:0;help:0;status:1');\" >yes</a>"                        
                        #<a class=\"fFriend\" id=\"execute\" href=\""+link+"\" onclick=javascript:initFRA()\">Yes</a>
                        tot += "<br>Do you want to send your friendship advertisement?<br>"+fralink+" - <a class=\"fFriend\" id=\"execute\" href=\"javascript:cancel('" + textSr[0] + "')>No</a><hr></li>"
                    tot += '</ul>'
                    me.send_response(200)
                    me.end_headers()
                    me.wfile.write(tot)
                    
                
                elif req["method"]=="find":
                    global finished, currentSearchResults, counter
                    finished = False
                    searchResults = {}
                    currentSearchResults = {}
                    
                    keyList = functions.getCombinations(req["key"])
                    counter = len(keyList)
                    global printed
                    printed= True
                    def delayed_res():
                        print "timeout reached for timer 1"
                        Ulogger.info("Method: find - timeout reached")
                        global printed
                        printed= False
                        global retrievedAllSearchData
                        retrievedAllSearchData = False
                       
                        showResult()
                        
                    
                    global time01,time02
#                    time01=threading.Timer(50*(len(keyList)+3),delayed_res)
                    time01=threading.Timer(30,delayed_res)
                    time01.start()
                    
                    
                    dfarr={}
                    def showResult():
                        global finished, retrievedAllSearchData, currentSearchResults, numberOfSearches, entryPoints, publicKeys, certUsers, certNodes
                        resultExists,retrievedAllSearchData, finished = False,False, False
                        tot = '<ul>'
                        entryPoints, publicKeys = {}, {}
                        print '========== UM: A total of '+str(len(searchResults.keys()))+' DHT lookup key has been searched'
                        for value, key in zip(searchResults.values(), searchResults.keys()):
                            
                            resultExists = True
                            for value2 in value:
                                reg_tok, cert_node, ip_addr,  time_v, isSSL = value2
                                reg_tok_data = reg_tok[0]
                                ret_sign = reg_tok[1]
                                cert_dhtlk, a = reg_tok_data
                                cert_user, ExpireTime = a
                                ret_dhtlk, ret_pkeyk, k_sign  = cert_dhtlk
                                ret_Uid, ret_pkeyU, u_sign  = cert_user
                                if not crypto.verify_tis_cert(cert_user) or not crypto.verify_tis_cert(cert_node):
                                    Ulogger.info("showResult - there is an invalid user in the system")
                                else:
								#FIXME TONY
                                    if ret_Uid not in entryPoints.keys():
                                        entryPoints[ret_Uid]=[]
                                    entryPoints[ret_Uid].append(FEP(cert_node, ip_addr, time_v, ExpireTime,isSSL))    
                                    publicKeys[ret_Uid] = ret_pkeyU
                                    certUsers[ret_Uid] = cert_user
                                    certNodes[ret_Uid] = cert_node
                        numberOfSearches = 0
                        resultExists = False
                        nUsersToFind=len(entryPoints.keys())						
                        print '========== UM: triggering profile data requests for '+str(nUsersToFind)+ ' users'
                        for key, value in zip(entryPoints.keys(), entryPoints.values()):
                            
							#TONY
#                            if (key in dispatcher.mat.FRT and dispatcher.mat.FRT[key].status == "FRIENDSHIP_ESTABLISHED") or key ==  dispatcher.mat.myFRE.cert_node[0]:
                            if key ==  dispatcher.mat.myFRE.cert_user[0]:
                                pass
                            else:
                                resultExists = True
                                numberOfSearches += 1
                                requestId=random.randint(1,100000000)
                                dispatcher.mat.DRM[key] = [DRE(dispatcher.mat.myFRE.cert_node[0], requestId)]
                                try:
                                    timestamp=int(round(time.time()))
                                except:
                                    print traceback.print_exc()
##########################################################################                                    
                                dispatcher.mat.DRM_chk[(key,requestId)]=[-1,-1,timestamp]
                                print '========== UM: triggering profile data requests for user '+str(binascii.hexlify(key))[0:4] +' to '+str(len(value))+' entrypoints'
                                dispatcher.mat.forwardPR(key, value, [0], ['find'],requestId)
                        
                        def delay_show():
                            print "========== UM: profile lookup timeout"
                            global retrievedAllSearchData
                            retrievedAllSearchData = True
                        #FIXME TONY 
                        time02=threading.Timer(min(50+5*nUsersToFind,70),delay_show)
                        #time02=threading.Timer((counter+3)*20,delay_show)
                        print '========== UM: profile lookup timer started'
                        time02.start()
                        
                        if not resultExists:
                            tot += '<li>No results found!</li>'
                            retrievedAllSearchData = True
                        
                        while not retrievedAllSearchData:
                            sleep(1)
                        time02.cancel()
                        print '========== UM: Current Search Result has '+str(len(currentSearchResults.values()))+' values'
                        for sr in currentSearchResults.values():
                            textSr = sr[:len(sr)-1]
                            tot += "<li><img src=\"./nowhere/search_" + textSr[0] + ".jpg\" onmousemove=\"showInfoBox('" + generateInfoBox(textSr) + "', event)\" onmouseout=\"hideInfoBox()\" ><br>"
                            link='FRA.html#userId='+textSr[0]+'?#userName='+textSr[1]+'?#status=1?'
                            fralink="<a class=\"fFriend\" id=\"execute\" href=\"#\" onclick=\"window.showModalDialog('"+link+"',null,'dialogWidth:500px;dialogHeight:350px;center:1;scroll:0;help:0;status:1');\" >Send " + textSr[1] + " a friendship advertisement</a>"                        
                        #"<a class=\"fFriend\" id=\"execute\" href=\" "+link+"\" onclick=\"javascript:initFRA()\">Send " + textSr[1] + " a friendship advertisement</a><hr></li>"
                            tot += fralink+"<hr></li>"
                        tot += '</ul>'
                        me.send_response(200)
                        me.end_headers()
                        me.wfile.write(tot)
                        finished = True
                    for key in keyList:
                        print '========== UM: recursive lookup for key '+str(binascii.hexlify(key))[0:4]
                        def addValue(result, k = key):
                            global counter
                            global printed
                            global time01
                            counter -= 1
                            print '========== UM: adding value of key '+str(binascii.hexlify(k))[0:4]
                            searchResults[k] = result
                            
                            if counter<= 0 and printed:
                                time01.cancel()
                                global retrievedAllSearchData
                                retrievedAllSearchData = False
                                showResult()
                                
                            return
                        def valueNotFound(result, k = key):
                            global counter
                            global printed
                            global time01
                            print '========== UM: key '+str(binascii.hexlify(k))[0:4]+'not found'
                            
							#FIXME TONY
                            counter -= 1
                            #if counter <= 0 and printed:
                            #    time01.cancel()
                            #    global retrievedAllSearchData
                            #    retrievedAllSearchData = False
                            #    showResult()
                            return
                        dfarr[key] = dispatcher.p2p.recursiveFind(key)
                        dfarr[key].addCallback(addValue)
                        dfarr[key].addErrback(valueNotFound)
                    timeoutcounter=0
                    while not finished:
                        if timeoutcounter==100:
                            return
                        sleep(1)
                        timeoutcounter+=1
                                        
                elif req["method"]=="sendBA":
                    
                    uid = binascii.unhexlify(req["uid"])
                    
                    def valueFound(result):
                        reg_tok, cert_node, ip_addr,  time_v, isSSL = result[0]
                        reg_tok_data = reg_tok[0]
                        ret_sign = reg_tok[1]
                        cert_dhtlk, a = reg_tok_data
                        cert_user, ExpireTime = a
                        ret_dhtlk, ret_pkeyk, k_sign  = cert_dhtlk
                        ret_Uid, ret_pkeyU, u_sign  = cert_user
                        if not crypto.verify_tis_cert(cert_user) or not crypto.verify_tis_cert(cert_node):
                            print 'unable to verify user/node certificates'
                        else:
                            badges=req["badges"].strip().split()
                            key_list=[]
                            for badge in badges:
                                k=usrmng.getKey(badge)
                                if k!=None:
                                    usrmng.dbm.addACP(req["uid"],usrmng.dbm.getBID(badge))
                                    key_list.append(k)
                            if len(key_list)==0:
                                key_list=[(0,'0')]
                            dispatcher.mat.sendBA(req["uid"], ret_pkeyU, [FEP(cert_node, ip_addr, time_v, ExpireTime,isSSL)], cert_user, cert_node,key_list)
                        return
                    def valueNotFound(result):
                        print "Recursive find failed"
                        return
                    
                    print "Looking for the entrypoints of ->"
                    print req["uid"]
                    df = dispatcher.p2p.recursiveFind2(uid)
                    df.addCallback(valueFound)
                    df.addErrback(valueNotFound)
                                            
                        
                elif req["method"]=="sendFA":
                    badges=req["badges"].strip().split()
                    key_list=[]
                    for badge in badges:
                        k=usrmng.getKey(badge)
                        if k!=None:
                            usrmng.dbm.addACP(req["userId"],usrmng.dbm.getBID(badge))
                            key_list.append(k)
                    if len(key_list)==0:
                        key_list=[(0,'0')]
                        
                    global advDelegateSent, entryPoints, publicKeys, certNodes, certUsers, currentSearchResults, friendshipRequests
                    advDelegateSent = False
                    print req["userId"]
                    uid = binascii.unhexlify(req["userId"])
                    
                    if req["status"] == "1":
                        #update PPI table in the database
                        ppiEntry = currentSearchResults[uid]
                        usrmng.dbm.addUpdatePPI(ppiEntry[0],ppiEntry[1],ppiEntry[2],ppiEntry[3],ppiEntry[4],ppiEntry[5],ppiEntry[6],ppiEntry[7],ppiEntry[8],ppiEntry[9],ppiEntry[10],ppiEntry[11],ppiEntry[12],ppiEntry[13],ppiEntry[14],ppiEntry[15],ppiEntry[16])
                        
                        lookUpData = (ppiEntry[1], ppiEntry[2], ppiEntry[4].split('/')[2], ppiEntry[5], ppiEntry[6])
                        dispatcher.mat.sendFRA(req["userId"], req["txtMsg"], publicKeys[uid], entryPoints[uid], certUsers[uid], certNodes[uid], lookUpData, req["status"],key_list)
                    
                    elif req["status"] == "2":
                        def valueFound(result):
                            reg_tok, cert_node, ip_addr,  time_v , isSSL= result[0]
                            reg_tok_data = reg_tok[0]
                            ret_sign = reg_tok[1]
                            cert_dhtlk, a = reg_tok_data
                            cert_user, ExpireTime = a
                            ret_dhtlk, ret_pkeyk, k_sign  = cert_dhtlk
                            ret_Uid, ret_pkeyU, u_sign  = cert_user
                            if not crypto.verify_tis_cert(cert_user) or not crypto.verify_tis_cert(cert_node):
                                print 'unable to verify user/node certificates'
                            else:
                                ppiEntry = friendshipRequests[req["userId"]]
#                                ppiEntry[16] = cStringIO.StringIO(sqlite3.Binary(ppiEntry[16])).getvalue()
                                usrmng.dbm.addUpdatePPI(ppiEntry[0],ppiEntry[1],ppiEntry[2],ppiEntry[3],ppiEntry[4],ppiEntry[5],ppiEntry[6],ppiEntry[7],ppiEntry[8],ppiEntry[9],ppiEntry[10],ppiEntry[11],ppiEntry[12],ppiEntry[13],ppiEntry[14],ppiEntry[15],ppiEntry[16])
                                
                                lookUpData = (ppiEntry[1], ppiEntry[2], ppiEntry[4].split('/')[2], ppiEntry[5], ppiEntry[6])
                                dispatcher.mat.sendFRA(req["userId"], req["txtMsg"], ret_pkeyU, [FEP(cert_node, ip_addr, time_v, ExpireTime,isSSL)], cert_user, cert_node, lookUpData, req["status"],key_list)
                                del friendshipRequests[req["userId"]]
                            return
                        def valueNotFound(result):
                            print "Recursive find failed"
                            return
                        
                        print "Looking for the entrypoints of ->"
                        print req["userId"]
                        df = dispatcher.p2p.recursiveFind2(binascii.unhexlify(req["userId"]))
                        df.addCallback(valueFound)
                        df.addErrback(valueNotFound)
                    
                    msg = '<SCRIPT LANGUAGE="javascript"> function closewin(){window.close();} closewin()</script>'
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(msg)
                    return    
                
                elif req["method"]=="podium":
                    # retrieve and write back my status (tweet) to the podium page
                    if req["id"]=='-1':
                        reqid=guid
                    else:                  
                        reqid = req["id"]
                    name = usrmng.dbm.retrieve("PPI", "NAME", reqid)
                    lastname = usrmng.dbm.retrieve("PPI", "LASTNAME", reqid)
                    query="SELECT CONTENT FROM PST WHERE UID='"+reqid+"' AND ISTWEET=1 ORDER BY TIME DESC"
                    tweets = usrmng.dbm.executeQuery(query)
                    if len(tweets)!=0:
                        statusMsg=tweets[0][0]
                    else:
                        statusMsg=''
                    mystatus = '<p><span class="userN">{0} {1} </span> {2}</p>'.format(name, lastname, statusMsg)
                    
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(mystatus)
                    return
                
                elif req["method"]=="threads":
                    # retrieve and write back all the threads in my wall to the podium (=wall) page
                    
                    start = '<ul><li>'
                    end = '</li></ul>'
                    tot = ''
                    
                    isSquare = False
                    if req["isSquare"] == "yes" : isSquare = True
                    
                    # GLI ID DEI PRIMI POST DEL WALL DI req["id"] ORDINATI PER TIME
                    if req["id"]=='-1':
                        reqid=guid
                    else:
                        reqid=req["id"]
                    if isSquare:
                        query1 = usrmng.queryStringPST(req["badge"])
                        tot+='<h2>Visibility: '+req["badge"]+'</h2>'
                    else:
                        query1 = 'SELECT ID FROM PST WHERE ID = FIRSTID AND UIDOWNER = "{0}" ORDER BY TIME DESC'.format(reqid,)
                    if query1!='':
                        records = usrmng.dbm.executeQuery(query1)
                    else:
                        records=[]
#                    print query1
                    noMessages = True
                    
                    total = ''
                    
                    for r in records:   # for each thread
                        query2 = 'SELECT UID, CONTENT FROM PST WHERE FIRSTID = "{0}" ORDER BY TIME'.format(r[0],)
                        posts = usrmng.dbm.executeQuery(query2)              
                        
                        tot += '<dl class="thread">'
                        isName = True
                        clas = 'name'
                        for p in posts: # for each post of the thread
                            name = usrmng.dbm.retrieve("PPI", "name", p[0])
                            lastname = usrmng.dbm.retrieve("PPI", "lastname", p[0])
                            #change the css class if not a new thread
                            if not isName:
                                clas = 'name1'
                            
                            if name is not None:
                                noMessages = False
                                avatar_name = "./nowhere/otherprof_%s.jpg"% p[0] # trick to generate a request for the avatar image (see later on)
                                
                                query1 = 'SELECT CONTENT FROM PST WHERE UIDOWNER = "{0}" AND ISTWEET = 1 AND UID = "{0}" ORDER BY TIME DESC'.format(p[0],)
                                '''if result is None:
                                    status = 'No status message yet!'
                                else:
                                    status = result[0][4]'''
                                status = usrmng.dbm.executeQuery(query1)
                        
                                if not status:
                                    status="_"
                                else:
                                    status=status[0][0]
                                
                                single_message = ('<dt><dl class="sender"> <dt class="dTitle">Full name:</dt><dd class="' + clas +
                                                  '"><a href="podium.html&{4}">{0} {1}</a>'
                                                  '</dd><dt class="dTitle">Avatar:</dt><dd class="avatar"><a href=""><img src={2} /></a></dd>'
                                                  '<dt class="dTitle">Status:</dt><dd class="status">{3}</dd><dt class="dTitleP"><a href="">Pictures'
                                                  '</a></dt><dd class="iconsP"><a href=""><img src="./img/ph.gif" /></a></dd><dt class="dTitleW">'
                                                  '<a href="podium.html&{4}">Wall</a></dt><dd class="iconsW"><a href=""><img src="./img/wa.gif" /></a></dd><dt class="dTitleM">'
                                                  '<a href="">Mail</a></dt><dd class="iconsM"><a href=""><img src="./img/ma.gif" /></a></dd></dl></dt>'
                                                  '<dd class="msg">{5}</dd>').format(name, lastname, avatar_name, status, p[0], p[1])
                                tot += single_message
                                isName = False
                        
                        if noMessages:
                            tot = ''
                        
                        # after having written all the posts of the thread, insert also the form to add another one
                        if not isName:
                            tot += ('<dt class="reply">reply:</dt> <p style="visibility: hidden;" id="threadid"></p>'
                                '<dd class="reply"><FORM class="replyF" action="" method="get">'
                                '<INPUT class="txt" type="text" id="newPost{0}" value="Write here your reply" onFocus="value=\'\'">'
                                '<p class="replyUp" onclick="javascript:insertComment({1})">Reply</p></form></dd></dl>').format(r[0], r[0])
                    
                    if tot == '':
                        tot = 'There are no posts at all'
                    
                    
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(start + tot + end)
                    return          
                #@Ali
                elif req["method"]=="galleryAlbums":
                    #print req["id"]
                    if req["uid"]=='-1' or req["uid"]=='null':
                        uidowner1=guid
                    else:
                        uidowner1=req["uid"]

                    if  req["aid"]!='0':
                        print "removing album"
                        queryString3='SELECT * FROM PCT WHERE aid='+req["aid"]+' AND uidowner="'+req["uid"]+'"'
                        try:
                            usrmng.dbm.executeQuery('DELETE FROM ALB WHERE aid='+req["aid"]+' AND uidowner="'+req["uid"]+'"')
                            usrmng.dbm.executeQuery('DELETE FROM DEK WHERE did='+req["aid"]+' AND type="ALB"')
                            pList=usrmng.dbm.executeQuery('SELECT * FROM PCT WHERE aid='+req["aid"]+' AND uidowner="'+req["uid"]+'"')
							# ===================================================================================TONY TODO: send profile data delete to mirrors==================
                        except:
                            print "galleryAlbums: error in deleting album"
                            Ulogger.info("method: galleryAlbums - error in deleting album")
                        for pItem in pList:
                            print "removing picture: "+ str(pItem[0])
                            try:
                                usrmng.dbm.executeQuery('DELETE FROM DEK WHERE did='+str(pItem[0])+' AND type="PCT"')
                                usrmng.dbm.executeQuery('DELETE FROM PCT WHERE id='+str(pItem[0])+' AND uidowner="'+req["uid"]+'"')
                                # =============TONY TODO: send profile data delete to mirrors=====================================================================================
                            except:
                                print "galleryAlbums: error in deleting album pictures"
                                Ulogger.info("method: galleryAlbums - error in deleting album pictures")
                    arows=usrmng.dbm.executeQuery('SELECT Aname, AID, IDTHUMB FROM ALB WHERE uidowner="'+uidowner1+'"')
                    albumString='<div id="sbAlbGall">'
					
                    for arow in arows:
                        aname,aid,idthumb=arow
                        if idthumb!=0:
                            prow=usrmng.dbm.executeQuery('SELECT ID,WIDTH,HEIGHT,FILETYPE,FILENAME,FILEDATA, FILEDESC FROM PCT WHERE id="{0}" AND aid="{1}"'.format(idthumb,aid))
                            if prow!=None:
                                id,w,h,filetype,filename,filedata,filedesc=prow[0]
                                imIn="web\\gallery\\"+str(id)+"."+filetype
                                f=open(imIn,"wb")
                                f.write(b64decode(filedata))
                                f.close()
                                path='./gallery/'+str(id)+'.'+filetype
                        
                        link='gallery.html#uid='+uidowner1+'?#aid='+str(aid)+'?#aname='+str(aname)+'?'
                        #albumString=albumString+'<a class="Album_show" href="'+link+'" onclick="javascript:showAlbum('"'Show Album Please'"', '+"'"+uidowner1+"','"+str(aid)+"','"+str(aname)+"','0"+"')"+'">'+aname+'</a><p></p>'
                        albumString=albumString+'<a href="'+link+'" title="'+aname+'" onclick="javascript:showAlbum('"'Show Album Please'"', '+"'"+uidowner1+"','"+str(aid)+"','"+str(aname)+"','0"+"')"+'"><div class="imgBlockAlb"><img '
                        if idthumb!=0:
                            if (w > h) :
                                albumString=albumString+'class="hor"'
                            else:
                                albumString=albumString+'class="ver"'
                            albumString=albumString+' src="'+path+'"'
                        else:
                            albumString=albumString+'class="hor" src="./img/albNoTh.jpg"'
                        albumString=albumString+' alt="'+aname+'" />'+aname+'</div></a>'
                    albumString=albumString+'</div>'
	
					
                    if req["uid"]=='-1' or req["uid"]=='null' or req["uid"]==guid:

                        albumString=albumString+'<FORM class="newAlbum" action="" method="get"><INPUT class="txt" type="text" id="albumName" value="Enter album\'s name here"><a class="addAlbumButton" href="javascript:addAlbum('"'Add new Album'"')">Add Album</a><img src="./img/sh.gif"></FORM>'				
                    
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(albumString)
                    return

                elif req["method"]=="addAlbum":
                    aid=usrmng.dbm.addUpdateAlbum(guid,req["name"],req["thumb"])
                    #@Ali content Format: [-,id(unique identifier for this data token),-,-,...]

					#default:public;
                    kid,key=usrmng.getKey('Private')
                    
                    counter=0
                    AlbTableRecord = [aid, guid, req["name"],req["thumb"] ]
                    fcount=usrmng.dbm.findMaxDEK()+1
                    EsDtok = ["ALB",fcount,kid, AlbTableRecord]
                    AEsDtok_d=b64encode(pickle.dumps(EsDtok, pickle.HIGHEST_PROTOCOL))
                    EsDtok=crypto.encrypt_AES(AEsDtok_d, key, IV)
                    item=[aid,fcount,kid,EsDtok]
                    dispatcher.mat.add(Job("R_MAT_PRS", item))

					#=============================================================================== SEND PRS
                    #dispatcher.mat.add(Job("R_MAT_PRS", EsDtok))
                    # make an insertion in DEK
#                    EsDtok=b64encode(pickle.dumps(EsDtok, pickle.HIGHEST_PROTOCOL))
                    usrmng.dbm.addUpdateDEK(aid,"ALB",kid,fcount,EsDtok)

                    #====================================================================
                    #print "TEST"
                    #queryString='SELECT * FROM DEK WHERE TYPE="ALB" AND DID="{0}"'.format(aid)
                    #try:
                    #    rows=usrmng.dbm.executeQuery(queryString)
                    #except:
                    #    print "newDKAss ERROR"
                    #Adid, Atype, Aoldkid, AoldCounter, AEsDtok=rows[0]
                    #print "in len: "+str(len(inData))+", out len: "+str(len(Aoldpikitem))
                    #AEsDtok=pickle.loads(b64decode(AEsDtok))
                    #print "original :"+AlbTableRecord[2]+" retrieved: "+AEsDtok[3][2]
					#=============================================================================
                    return

                elif req["method"]=="showAlbum":
				
                    if req["pid"]!='0' and req["pid"]!='undefined':
                        try:
                            rows=usrmng.dbm.executeQuery('DELETE FROM PCT WHERE id='+req["pid"]+' AND uidowner="'+req["uidowner"]+'"')
                            usrmng.dbm.executeQuery('DELETE FROM DEK WHERE did='+req["pid"]+' AND type="PCT"')
							# ===================================================================================TONY TODO: remove this item from  mirrors
                        except:
                            print "showAlbum: error in deleting picture"
                            Ulogger.info("method: showAlbum - Error in deleting picture")
                        
						
                    queryString='SELECT ID,WIDTH,HEIGHT,FILETYPE,FILENAME,FILEDATA, FILEDESC FROM PCT WHERE aid='+req["aid"]+' AND uidowner="'+req["uidowner"]+'"'
                    queryString2='SELECT ANAME FROM ALB WHERE AID="'+req["aid"]+'"'
                    try:
                        rows=usrmng.dbm.executeQuery(queryString)
                        rows2=usrmng.dbm.executeQuery(queryString2)
                    except:
                        Ulogger.info("method: showAlbum - No entry found")
                        return
					
                    link='http://localhost:8080/gallery.html#uid='+req["uidowner"]+'?'
                    tablestring='<div class="aname">'+rows2[0][0]+'</div><div class="goback"><p><a href='+link+' onclick="javascript:getGalleryAlbums('"'Show Albums Please'"',  '+"'"+req["uidowner"]+"', '0'"+')">Go back to Albums</a></p></div>'
                    tablestring=tablestring+'<div id="sbGall">'
                    #print "showAlbum - aid: "+req["aid"]+"aname: "+rows2[0][0]+"uidowner:"+req["uidowner"]+"pid:"+req["pid"]
                    for row in rows:
                        id,w,h,filetype,filename,filedata,filedesc=row
                        imIn="web\\gallery\\"+str(id)+"."+filetype

                        f=open(imIn,"wb")
                        f.write(b64decode(filedata))
                        f.close()

                        path='./gallery/'+str(id)+'.'+filetype
                        link='gallery.html#uid='+req["uidowner"]+'?#aid='+req["aid"]+'?#pid='+str(id)+'?'
                        tablestring=tablestring+'<a href="'+link+'" title="'+filedesc+'" onclick="javascript:showPicture('"'Show Picture Please'"', '+"'"+str(id)+"','"+req["uidowner"]+"','"+req["aid"]+"','"+rows2[0][0]+"'"+')">'
                        tablestring=tablestring+'<div class="imgBlock"><img '
                        if (w > h) :
                            tablestring=tablestring+'class="hor"'
                        else:
                            tablestring=tablestring+'class="ver"'
                        tablestring=tablestring+' src="'+path+'" alt="'+filedesc+'" /></div></a>'
                    tablestring=tablestring+'</div>'
                    if req["uidowner"]==guid:
                        albLink='http://localhost:8080/gallery.html#uid='+req["uidowner"]+'?#aid='+req["aid"]+'?#aname='+rows2[0][0]+'?'
                        tablestring=tablestring+'<div class="upPhoto"><FORM class="UploadPhotoForm" action="'+albLink+'" method="post"  enctype="multipart/form-data"><INPUT type="file" name="imgfile" id="photoPath" value="Upload new Photo"><INPUT type="text" name="PCTdesc" value="Add Description"><input class="hiddenField" type="text" name="uid" value="'+req["uidowner"]+'"><input class="hiddenField" type="text" name="aname" value="'+rows2[0][0]+'"><input class="hiddenField" type="text" name="command" value="newPct"><input class="hiddenField" type="text" name="aid" value="'+req["aid"]+'"><input class="okFileUp" type="submit" name="submit" value="OK" /></FORM></div>'
                        tablestring=tablestring+'<div class="goback"><p><a href="'+link+'#aid="'+req["aid"]+'" onclick="javascript:getGalleryAlbums('"'Remove Album Please'"', '+"'"+req["uidowner"]+"', '"+req["aid"]+"'"+')">Remove this album.</a></p></div>'	
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(tablestring)
                    return
                elif req["method"]=="showAlbumBadges":
                    if req["id"]==guid or req["id"]=='-1':
                        queryString="SELECT BID,BadgeName FROM BDG WHERE BadgeName<>'Private' ORDER BY BadgeName"
                        queryString2='SELECT Key_ID from DEK WHERE Type="ALB" AND DID="'+req["aid"]+'"'
                        #print "query2 is: "+queryString2
                        try:
                            rows=usrmng.dbm.executeQuery(queryString)
                            rows2=usrmng.dbm.executeQuery(queryString2)
                        except:
                            print "showAlbumBadges ERROR"
                            #Ulogger.info("method: showAlbumBadges - No badges found")
                            return
                        symKeyAlbum=rows2[0][0]
    					
                        queryString3='SELECT BID FROM BKR WHERE Key_ID = "'+str(symKeyAlbum)+'"'
                        try:
                            rows3=usrmng.dbm.executeQuery(queryString3)
                        except:
                            Ulogger.info("method: showAlbumBadges - unable to get the list of badges associated to the key encrypting the album")
                            return
    					
                        albLink='http://localhost:8080/gallery.html#uid='+req["uidowner"]+'?#aid='+req["aid"]+'?'
    					
                        answer='<FORM class="UploadAlbumACP" action="'+albLink+'" method="post"  enctype="multipart/form-data"><fieldset><legend>Badges</legend>'
                        for row in rows:
                            bid,bname=row
                            answer=answer+'<label for="'+str(bid)+'">'+bname+'</label><input type="checkbox" value="'+bname+'" name="'+str(bid)+'"'
                            for r in rows3:
                                if r[0]==bid:
                                    answer=answer+" checked"
                            answer=answer+"/><br>"
                        answer=answer+'<input class="hiddenField" type="text" name="command" value="newDKAss"><input class="hiddenField" type="text" name="aid" value="'+req["aid"]+'"></fieldset><input class="okIn" type="submit" name="modify" value="Modify Visibility"></form>'
    
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(answer)
                    return
                elif req["method"]=="showPicture":

                    queryString='SELECT ID,WIDTH,HEIGHT,FILETYPE,FILENAME,FILEDATA, FILEDESC FROM PCT WHERE id='+req["pid"]+' AND uidowner="'+req["uidowner"]+'"'
                    try:
                        rows=usrmng.dbm.executeQuery(queryString)
                    except:
                        Ulogger.info("method: showPicture - No picture found")
                        return

                    link='gallery.html#uid='+req["uidowner"]+'?#aid='+req["aid"]+'?'
                    tablestring='<div class="goback"><p><a class="Album_show" href="'+link+'" onclick="javascript:showAlbum('"'Show Album Please'"', '+"'"+req["uidowner"]+"','"+req["aid"]+"','"+req["aname"]+"','0"+"')"+'">go back to album '+req["aname"]+'</a></p></div>'
                    tablestring=tablestring+'<div id="sbPct">'
                    for row in rows:
                        id,w,h,filetype,filename,filedata_enc,filedesc=row
#                        filedata=crypto.decrypt_AES(filedata_enc, sKey[1], IV)
                        path='./gallery/'+str(id)+'.'+filetype
                        tablestring=tablestring+'<img '
                        if (w > h) :
                            tablestring=tablestring+'class="hor2"'
                        else:
                            tablestring=tablestring+'class="ver2"'
                        tablestring=tablestring+' src="'+path+'" alt="'+filedesc+'" />'
                    tablestring=tablestring+'</div>'
                    #link='gallery.html#uid='+req["uidowner"]+'?#aid='+req["aid"]+'?'
                    if req["uidowner"]==guid:
                        tablestring=tablestring+'<div><p><a href="'+link+'" onclick="javascript:showAlbum('"'Remove Picture Please'"', '+"'"+req["uidowner"]+"','"+req["aid"]+"','"+req["aname"]+"','"+req["pid"]+"'"+')">Remove this picture.</a></p></div>'


                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(tablestring)
                    return
					
                
                #@Ali
                elif req["method"]=="getBadge":
                    uid=req["id"]
                    if uid=='-1':
                        uid=guid
                    if req["isSquare"]=='yes':
                        page='square'
                        flag='0'
                    else:
                        page='podium'
                        flag='1'
#                            <div id="sbBadge">
                    returnString='<ul><li><h3>YOUR BADGES</h3><p></p>'
                    queryString="SELECT BadgeName FROM BDG WHERE BadgeName<>'Private'"
                    try:
                        rows=usrmng.dbm.executeQuery(queryString)
                    except:
                        print 'No badge found'
                        return
                    for row in rows:
                        badgeName,=row
                        link='http://localhost:8080/'+page+'.html#uid='+uid+'?#badge='+badgeName+'?'
#                        returnString+='<a href="'+link+'" onclick="javascript:initPodium('+'0'+')"'+'>'+badgeName+'</a><br>'
                        returnString+='<a href="'+link+'" onclick="javascript:refreshpage()"'+'>'+badgeName+'</a><br>'
                    returnString+='</li></ul>'

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(returnString)
                    return
                elif req["method"]=="getBadgeCheckBox":
                    #returnString='<div id="sbBadge" align="center"><h3>FRIENDSHIP REQUEST</h3><p><b>To: '+req["userName"]+'</b></p><h4>Add Badges in Friendship Request</h4><p></p><form name="userBadges" action="javascript:add()" method="get"><b>Request Message:</b><input type="text" id="msg" value="I would like to add you as a friend"><table border="1" align="left"><tr><td>'
                    returnString='<div id="bHeader"><h2>Friendship Advertisement to: '+req["userName"]+'</h2></div><form name="userBadges" action="javascript:add()" method="get"><div id="bLeft"><label for="msg">Request Message:</label><br /><textarea id="msg"> I consider you as a friend </textarea></div><div id="bRight"><label for="">Available Badges:</label><br />'
                    queryString="SELECT BadgeName FROM BDG WHERE BadgeName<>'Private'"
                    try:
                        rows=usrmng.dbm.executeQuery(queryString)
                    except:
                        print 'No badge found'
                        return
                    for row in rows:
                        badgeName,=row
                        if badgeName!="Public" and badgeName!="Private":
                            returnString+='<input type="checkbox" name="badge" value="'+badgeName+'" />'+badgeName+'<br />'
                    returnString+='</div><div id="bFooter"><input value="Submit" type="submit"></div></form>'
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(returnString)
                    return
                elif req["method"]=="getFriendBadges":
                    uid=req["uid"]
                    if uid=='-1' or uid==guid:
                        returnString=''
                    else:
                        returnString='<ul><li><h3>Friend Visibility</h3><p></p>'
                        queryString="SELECT BID FROM ACP WHERE UIDOWNER='"+req["uid"]+"'"
                        try:
                            bids=usrmng.dbm.executeQuery(queryString)
                        except:
                            print 'No badge found'
                            return
                        for bid in bids:
                            badgeName=usrmng.dbm.getBadge(bid[0])
                            returnString+='<p>'+badgeName+'</p>'
#                        returnString+=
                        link='advertise.html#uid='+uid+'?'
                        
                        advLink="<a class=\"NewBadges\" id=\"execute\" href=\"#\" onclick=\"window.showModalDialog('"+link+"',null,'dialogWidth:225px;dialogHeight:250px;center:1;scroll:0;help:0;status:0');\" ><b>Add more Badges</b></a></li></ul>"                        
                        #<a class=\"fFriend\" id=\"execute\" href=\""+link+"\" onclick=javascript:initFRA()\">Yes</a>
                        returnString +=advLink

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(returnString)
                    return
                elif req["method"]=="getCommentAccessBadges":
                    def formatUrlInput(s):
                        s_list=s.split('%20')
                        if len(s_list)==1:
                            return s
                        returnVal=''
                        for element in s_list:
                            returnVal+=element+' '
                        return returnVal[0:len(returnVal)-1]
                    req["threadid"]=formatUrlInput(req["threadid"])

                    #returnString='<div id="sbBadge" align="center"><h3>Visibility Options</h3><p></p><form name="userBadges" action="javascript:closeInsertComment()" method="get"><table border="1" align="left"><tr><td>'
                    returnString='<div id="statBHeader"><h3>Visibility Options</h3><form name="userBadges" action="javascript:closeInsertComment()" method="get"><div id="statBBody"><label for="">Available Badges:</label><br>'
                    bn_chked=''
                    if req["threadid"]=='AnewThread':
                        queryString_BDG="SELECT BadgeName FROM BDG WHERE BadgeName<>'Private'"
                        rows_bn=usrmng.dbm.executeQuery(queryString_BDG)
                    else:
# The following block is for when u need visibility option only for badges you hold for thread owner, if u r thread owner u have all badges.
#                        queryString="SELECT ID,UIDOWNER FROM PST WHERE ID="+req["threadid"]
#                        rows=usrmng.dbm.executeQuery(queryString)
#                        id,uid,=rows[0]
#                        if uid==guid:
#                            queryString_BDG="SELECT BadgeName FROM BDG WHERE BadgeName<>'Private'"
#                            rows_bn=usrmng.dbm.executeQuery(queryString_BDG)
#                            q1="SELECT Key_ID FROM DEK WHERE TYPE='PST' AND DID="+id
#                            kid_chked=usrmng.dbm.executeQuery(q1)
#                            q2="SELECT BID FROM BKR WHERE Key_ID="+str(kid_chked[0][0])
#                            bid_chked=usrmng.dbm.executeQuery(q2)
#                            bn_chked=usrmng.dbm.getBadge(str(bid_chked[0][0]))
#                        else:
#                            queryString_acp="SELECT BID FROM ACP WHERE UIDOWNER='"+uid+"'"
#                            rows_acp=usrmng.dbm.executeQuery(queryString_acp)
#                            rows_bn=[]
#                            for row in rows_acp:
#                                bid,=row
#                                bn=usrmng.dbm.getBadge(bid)
#                                rows_bn.append((bn,)) 
###########################################################################################   
                        queryString="SELECT ID,UIDOWNER FROM PST WHERE ID="+req["threadid"]
                        rows=usrmng.dbm.executeQuery(queryString)
                        id,uid,=rows[0]
                        if uid==guid:
                            queryString_BDG="SELECT BadgeName FROM BDG WHERE BadgeName<>'Private'"
                            rows_bn=usrmng.dbm.executeQuery(queryString_BDG)
                            q1="SELECT Key_ID FROM DEK WHERE TYPE='PST' AND DID="+id
                            kid_chked=usrmng.dbm.executeQuery(q1)
                            q2="SELECT BID FROM BKR WHERE Key_ID="+str(kid_chked[0][0])
                            bid_chked=usrmng.dbm.executeQuery(q2)
                            if bid_chked:
                                bn_chked=usrmng.dbm.getBadge(str(bid_chked[0][0]))
                            else:
                                bn_chked=usrmng.dbm.getBadge(0) #esko:fix, now one can reply to public message
                        else:
                            queryString_BDG="SELECT BadgeName FROM BDG WHERE BadgeName<>'Private'"
                            rows_bn=usrmng.dbm.executeQuery(queryString_BDG)
                            queryString_acp="SELECT BID FROM ACP WHERE UIDOWNER='"+uid+"'"
                            rows_acp=usrmng.dbm.executeQuery(queryString_acp)
                            rows_bn_sugestions=[]
                            returnString+='<h3>Suggestions: The thread owner hold the following Badges</h3><br/>'
                            for row in rows_acp:
                                bid,=row
                                bn=usrmng.dbm.getBadge(bid)
                                returnString+='<p>'+bn+'</p><br/>'                    
                    for row in rows_bn:
                        badgeName,=row
                        if badgeName==bn_chked:
                            returnString+='<input type="radio" checked="yes" name="badge" value="'+badgeName+'" />'+badgeName+'<br />'
                        else:
                            returnString+='<input type="radio" name="badge" value="'+badgeName+'" />'+badgeName+'<br />'
                    #returnString+='</td></tr></table><p></p><input type="submit" value="Submit" /></form></div>'
                    returnString+='</div><div id="statBFooter"><input value="Submit" type="submit"></div></form></div>'
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(returnString)
                    return
                        
                elif req["method"]=="initKeyAdvertise":
                    #returnString='<div id="sbBadge" align="center"><h3>Visibility Options</h3><h4>Send the checked Badges to my Friend</h4><p></p><form name="userBadges" action="javascript:closeAdv()" method="get"><table border="1" align="left"><tr><td>'
                    returnString='<div id="statBHeader"><h3>Badge Distribution</h3><form name="userBadges" action="javascript:closeAdv()" method="get"><div id="statBBody">'
                    queryString0="SELECT BID FROM ACP WHERE UIDOWNER='"+req["uid"]+"'"
                    try:
                        bids=usrmng.dbm.executeQuery(queryString0)
                    except:
                        print 'No badge found'
                        return
                                        
                    queryString="SELECT BadgeName FROM BDG WHERE BadgeName<>'Private'"
                    if len(bids)!=0:
                        queryString+=' AND'
                    for bid in bids:
                        queryString+= ' BID<>'+str(bid[0])+' AND'
                    if len(bids)!=0:
                        queryString=queryString[0:len(queryString)-3]
                    try:
                        rows=usrmng.dbm.executeQuery(queryString)
                    except:
                        print 'No badge found'
                        return
                    for row in rows:
                        badgeName,=row
                        returnString+='<input type="checkbox" name="badge" value="'+badgeName+'" />'+badgeName+'<br />'
                    #returnString+='</td></tr></table><p></p><input type="submit" value="Submit" /></form></div>'
                    returnString+='</div><div id="statBFooter"><input value="Submit" type="submit"></div<></form></div>'
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(returnString)
                    return
                elif req["method"]=="insert":
                    #print "<<<<<<<<<<Insert method called-----------"
                    def formatUrlInput(s):
                        s_list=s.split('%20')
                        if len(s_list)==1:
                            return s
                        returnVal=''
                        for element in s_list:
                            returnVal+=element+' '
                        return returnVal[0:len(returnVal)-1]
                    req["threadid"]=formatUrlInput(req["threadid"])
                    req["post"]=formatUrlInput(req["post"])
                    
                    if req["id"]=='-1':
                        req["id"]=guid
                    #print "BADGE LIST: "+str(req["badge"])
                    if req["badge"]=='Square':
                        query01="SELECT UIDOWNER FROM PST WHERE ID = '"+req["threadid"]+"'"
                        id_own = usrmng.dbm.executeQuery(query01)
                        if id_own[0]==guid:
                            query00="SELECT Key_ID FROM DEK WHERE TYPE='PPI' AND DID = '"+req["threadid"]+"'"
                            kid=usrmng.dbm.executeQuery(query00)
                            if kid!=None:
                                key_val=self.dbm.getkeyDKR(kid)
                                key=(kid,key_val)
                            else:
                                key=(0,0)
                        else:
                            query02="SELECT BID FROM ACP WHERE UIDOWNER = '"+id_own[0][0]+"'"
                            bid_l=usrmng.dbm.executeQuery(query02)
                            key=(0,0)
                            for b in bid_l:
                                if b[0]!=0:
                                    key=usrmng.getKey(usrmng.dbm.getBadge(b[0]))
                                    break
                    else:
                        #print "Getting key for badge: "+str(req["badge"])
                        key=usrmng.getKey(req["badge"])
                        if key==None:
                            print 'No Key found for Badge = '+req["badge"]
                            return
                    isSquare = False
                    #print "IsSquare value: "+str(req["isSquare"])
                    if req["isSquare"] == "yes" : isSquare = True
                
                    time_v = datetime.datetime.now()
                    
                    query1 = 'SELECT MAX(ID) FROM PST'
                    pid = random.randint(0,10000)
                    
                    if req["threadid"] == "AnewThread":
                        firstpid = pid
                    else:
                        firstpid = req["threadid"]
                    
                    isTweet = 0
                    if req["id"] == guid and firstpid == pid:
                        isTweet = 1
                    
                    #@Ali post can be encrypted with group key defined in badges
                    #print "updating PST table with the new post: "+str(req["post"])
                    usrmng.dbm.addUpdatePost(pid,guid, req["id"], req["post"], time_v, isTweet, firstpid)
                    row = [pid,guid, req["id"], req["post"], time_v, isTweet, firstpid]
                    fcount=usrmng.dbm.findMaxDEK()+1
                    content=['PST',fcount,key[0],row]
                    if key[0]==0:
                        encryptedPost=str(b64encode(pickle.dumps(content,2)))
                    else:
                        encryptedPost=crypto.encrypt_AES(str(b64encode(pickle.dumps(content,2))), key[1], IV)
                    
                    usrmng.dbm.addDEK(pid,"PST",key[0],fcount,encryptedPost)
                    #@Ali content Format: [-,id(unique identifier for this data token),-,-,...]
                    
                    item = [pid,fcount,key[0],encryptedPost]
                    dispatcher.mat.add(Job("R_MAT_PRS", item))
                    
                    start = '<ul><li>'
                    end = '</li></ul>'
                    tot = ''
                    total = ''
                    if isSquare:
                        query1 = usrmng.queryStringPST(req['badge'])
                        tot+='<h2>Visibility: '+req["badge"]+'</h2>'
                    else:
                        query1 = 'SELECT ID FROM PST WHERE ID = FIRSTID AND UIDOWNER = "{0}" ORDER BY TIME DESC'.format(req["id"],)
#                    print query1
                    if query1!='':
                        records = usrmng.dbm.executeQuery(query1)
                    else:
                        records=[]
                    noMessages = True
                    
                    
                    
                    for r in records:   # for each thread
                        query2 = 'SELECT UID, CONTENT FROM PST WHERE FIRSTID = "{0}" ORDER BY TIME'.format(r[0],) 
                        posts = usrmng.dbm.executeQuery(query2)                       
                        
                        tot += '<dl class="thread">'
                        isName = True
                        clas = 'name'
                        for p in posts: # for each post of the thread
                            name = usrmng.dbm.retrieve("PPI", "name", p[0])
                            lastname = usrmng.dbm.retrieve("PPI", "lastname", p[0])
                            #change the css class if not a new thread
                            if not isName:
                                clas = 'name1'
                            
                            if name is not None:
                                noMessages = False
                                avatar_name = "./nowhere/otherprof_%s.jpg"% p[0] # trick to generate a request for the avatar image (see later on)
                                
                                query1 = 'SELECT CONTENT FROM PST WHERE UIDOWNER = "{0}" AND ISTWEET = 1 AND UID = "{0}" ORDER BY TIME DESC'.format(p[0],)
                                '''if result is None:
                                    status = 'No status message yet!'
                                else:
                                    status = result[0][4]'''
                                status = usrmng.dbm.executeQuery(query1)
                        
                                if not status:
                                    status="_"
                                else:
                                    status=status[0][0]
                                
                                single_message = ('<dt><dl class="sender"> <dt class="dTitle">Full name:</dt><dd class="' + clas +
                                                  '"><a href="podium.html&{4}">{0} {1}</a>'
                                                  '</dd><dt class="dTitle">Avatar:</dt><dd class="avatar"><a href=""><img src={2} /></a></dd>'
                                                  '<dt class="dTitle">Status:</dt><dd class="status">{3}</dd><dt class="dTitleP"><a href="">Pictures'
                                                  '</a></dt><dd class="iconsP"><a href=""><img src="./img/ph.gif" /></a></dd><dt class="dTitleW">'
                                                  '<a href="podium.html&{4}">Wall</a></dt><dd class="iconsW"><a href=""><img src="./img/wa.gif" /></a></dd><dt class="dTitleM">'
                                                  '<a href="">Mail</a></dt><dd class="iconsM"><a href=""><img src="./img/ma.gif" /></a></dd></dl></dt>'
                                                  '<dd class="msg">{5}</dd>').format(name, lastname, avatar_name, status, p[0], p[1])
                                tot += single_message
                                isName = False
                        
                        if noMessages:
                            tot = ''
                        
                        # after having written all the posts of the thread, insert also the form to add another one
                        if not isName:
                            tot += ('<dt class="reply">reply:</dt> <p style="visibility: hidden;" id="threadid"></p>'
                                '<dd class="reply"><FORM class="replyF" action="" method="get">'
                                '<INPUT class="txt" type="text" id="newPost{0}" value="Write here your reply" onFocus="value=\'\'">'
                                '<p class="replyUp" onclick="javascript:insertComment({1})">Reply</p></form></dd></dl>').format(r[0], r[0])
                    
                    if tot == '':
                        tot = 'There are no posts at all'
                    
                    
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(start + tot + end) 
                    return
                    
            elif (self.path.find("nowhere")!=-1):       # trick to retrieve new resource from database
                                                        # "./nowhere/prof_%s.jpg" or "./nowhere/myavatar.jpg"
                
                if (self.path.find("myavatar")!=-1):    # it is a request for my avatar image
                    if req['id'] == -1 or req['id'] is None:
                        prid = guid
                    else:
                        prid = req["id"]
                    avatar = usrmng.dbm.retrieve("PPI", "avatar", prid)
                    self.send_response(200)
                    self.send_header('Content-type', 'image/jpg') 
                    self.end_headers()
                    self.wfile.write(avatar)
                    return
                
                if (self.path.find("otherprof")!=-1):        # it is a request for avatar image of a contact
                    uid = self.path.split("_")[1].split(".")[0]
                    if uid=="-1":
                        uid = guid
                    avatar = usrmng.dbm.retrieve("PPI", "avatar", uid)
                    self.send_response(200)
                    self.send_header('Content-type', 'image/jpg') 
                    self.end_headers()
                    self.wfile.write(avatar)
                    return
                
                if (self.path.find("search")!=-1):        # it is a request for avatar image of a contact
                    global currentSearchResults
                    id = self.path.split("_")[1].split(".")[0]
                    avatar = cStringIO.StringIO(sqlite3.Binary(b64decode(currentSearchResults[binascii.unhexlify(id)][16]))).getvalue()
                    self.send_response(200)
                    self.send_header('Content-type', 'image/jpg') 
                    self.end_headers()
                    self.wfile.write(avatar)
                    return
                
                if (self.path.find("friend")!=-1):        # it is a request for avatar image of a contact
                    global friendshipRequests
                    id = self.path.split("_")[1].split(".")[0]
                    avatar = friendshipRequests[id][len(friendshipRequests[id])-2]
                    self.send_response(200)
                    self.send_header('Content-type', 'image/jpg') 
                    self.end_headers()
                    self.wfile.write(b64decode(avatar))
                    return
            
            else:                    
                req = curdir + sep + "web" + sep + self.path
                self.send_response(200)
                #TONY INSERTION
                f = None
                
                if self.path.find(".html")!=-1: # if it is a request for an html page
                    realfile = req.split("&")[0]
                    f = open(realfile, "r")
                    
                    if self.path.find("podium")!=-1 or self.path.find("square")!=-1 or self.path.find("profile")!=-1:   # for the html page of the podium (wall)
                        if self.path.find("&")!=-1:     # if the request is something like podium.html&id_number
                            id=self.path.split("&")[1]
                            if id == '-1':
                                id=guid
                            global openpageid
                            openpageid = id
                            pag = f.read()
                            pag = pag.replace("targetUID",id)   # replace the string "targetUID" in the podium.html with the requested id_number
                                                            # in this way, the ajax script will know the owner id of the podium
                                                            # and will ask with req["podium"] the proper data (req["id"])
                            self.send_header('Content-type', 'text/html')
                            self.end_headers()
                            self.wfile.write(pag)
                            f.close()
                            return
                            
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
                    f = open(req, "rb")
                    self.send_header('Content-type', 'text/ico')
                elif self.path.endswith(".js"):
                    f = open(req, "r")
                    self.send_header('Content-type', 'application/x-javascript')
  # TONY MOD
  # this else is not useful
                else:
					#FIXME==============================================================
                    #print "Unuseful page request - no content specified"
					#=====================================================================
                    realfile='profile.html'
                    global openpageid
                    openpageid = guid
                    f = open('web'+os.sep+realfile, "r")
                    pag=f.read()
                    pag = pag.replace("targetUID",openpageid)
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(pag)
                    f.close()
                    f=None
                  
                    
                if f!= None:
                    self.end_headers()
                    self.wfile.write(f.read())
                    f.close()

        except IOError:
			#FIXME
            #self.send_error(404,'File Not Found: %s' % self.path)
            pass
        except:
		    #FIXME
            #print traceback.print_exc()
            pass
    
	#FIXME
    # UNCOMMENT THIS TO SUPPRESS ALL THE HTTP LOG ON SCREEN (overwrites the log_message method)
    #def log_message(self, *format):
    #        pass 

    def do_POST(self):

#        iv='\0'* (AESKLEN/8)
        try:
            form = cgi.FieldStorage(
                fp=self.rfile, 
                headers=self.headers,
                environ={'REQUEST_METHOD':'POST',
                         'CONTENT_TYPE':self.headers['Content-Type'],
                         })
    					 # Begin the response
            if form["command"].value == 'newPct':
    	    	# Echo back information about what was posted in the form
                for field in form.keys():
                    field_item = form[field]
                    if field_item.filename:
                        # The field contains an uploaded file
                        filename=field_item.filename
                        file_data = field_item.file.read()
                        file_len = len(file_data)
                        filetype=filename.split('.')[1]
                        #del file_data
                        #self.wfile.write('\tUploaded %s as "%s" (%d bytes)\n' % \
                         #       (field, field_item.filename, file_len))
                    else:
                        pass
                        # Regular form value
                        #self.wfile.write('\t%s=%s\n' % (field, form[field].value))
    
                try:
                    file_data			
                    aid=form["aid"].value
                    uid=form["uid"].value
                    desc=form["PCTdesc"] .value
                    aname=form["aname"].value
                    temp_file=open("temp.jpg","wb")
    
                    temp_file.write(buffer(file_data, 0, file_len))
                    temp_file.close()
                
                    newPct=Image.open("temp.jpg")
    
    	    		# current key encrypting album's picture
                    queryString='SELECT DEK.Key_ID, KEY FROM DEK, DKR WHERE DEK.KEY_ID=DKR.KEY_ID AND Type="ALB" AND DID="{0}"'.format(form["aid"].value)
                    try:
                        rows=usrmng.dbm.executeQuery(queryString)
                    except:
                        print "newPCT ERROR"
                        Ulogger.error("method: newPct - unable to find the key currently encrypting pictures of album "+aid)
                        return
                    if rows!=[]:
                        kid=rows[0][0]
    			    	# key is in B64
                        skey=b64decode(rows[0][1])
    
                    else:
                        kid=0
    			
    			
                    #id=usrmng.dbm.addUpdatePicture(strftime("%Y-%m-%d %H:%M:%S", gmtime()),uid,aid,newPct.size[0],newPct.size[1],filetype,filename,encryptedPCT[0:], desc)               
                    id=usrmng.dbm.addUpdatePicture(uid,strftime("%Y-%m-%d %H:%M:%S", gmtime()),aid,newPct.size[0],newPct.size[1],filetype,filename,b64encode(file_data), desc)
                        
                    #@Ali content Format: [-,id(unique identifier for this data token),-,-,...]
                    PctTableRecord = [id,uid,strftime("%Y-%m-%d %H:%M:%S", gmtime()),aid,newPct.size[0],newPct.size[1],filetype,filename,b64encode(file_data), desc]
                    fcount=usrmng.dbm.findMaxDEK()+1
                    PEsDtok = ["PCT", fcount,kid, PctTableRecord]
                    PEsDtok=b64encode(pickle.dumps(PEsDtok, pickle.HIGHEST_PROTOCOL))
                    if kid!=0:
                        PEsDtok=crypto.encrypt_AES(PEsDtok, skey,IV)
                
    			
                    # store the new association between DID and KID in DEK, ESTDTOK 
                    usrmng.dbm.addUpdateDEK(id,"PCT",kid,fcount,PEsDtok)
                    item=[id,fcount,kid,PEsDtok]
                    #=================================================================================SEND PRS!!
                    dispatcher.mat.add(Job("R_MAT_PRS", item))
                
                    # update the thumbnail if necessary
                    arows=usrmng.dbm.executeQuery('SELECT IDTHUMB, Aname FROM ALB WHERE AID="'+form["aid"].value+'"')
                    if arows[0][0]==0:
    #                    print "updating thumbnail for album " + arows[0][1]
                        aid=usrmng.dbm.addUpdateAlbum(guid,arows[0][1],id,int(form["aid"].value))
                        
                        AlbTableRecord = [aid, guid, arows[0][1],id ]
                        fcount=usrmng.dbm.findMaxDEK()+1
                        EsDtok = ["ALB",fcount,kid, AlbTableRecord]
                        EsDtok=b64encode(pickle.dumps(EsDtok, pickle.HIGHEST_PROTOCOL))
                        if kid!=0:
                            EsDtok=crypto.encrypt_AES(EsDtok, skey,IV)
                        usrmng.dbm.addUpdateDEK(aid,"ALB",kid,fcount,EsDtok)
                        item=[aid,fcount,kid,EsDtok]
                        dispatcher.mat.add(Job("R_MAT_PRS", item))
    
                    del file_data
    
                except:
                    #trying to insert a picture without defining its path..
                    pass
            elif form["command"].value == 'newDKAss':
    
    			# get the new badge settings
                newSett=form.keys()
                newSett.sort()
    			#last two keys do not represent badge ids
                newSett=newSett[:-3]
    
    			# current version of data
                queryString='SELECT * FROM DEK WHERE Type="ALB" AND DID="{0}"'.format(form["aid"].value)
                try:
                    rows=usrmng.dbm.executeQuery(queryString)
                except:
                    print "newDKAss ERROR"
                    Ulogger.info("method: newDKAss - Album was not found in DEK")
                    return
    			#AEsDtok is base64, it should be kept  like this
                Adid, Atype, Aoldkid, AoldCounter, AEsDtok=rows[0]
    #            print "AesDtok of len "+str(len(AEsDtok))+" has been retrieved: "+str(AEsDtok)
                if AoldCounter==None:
                    AoldCounter=0
    
    				
    			#retrieve the old and new key value from DKR
                if Aoldkid != 0:
                    queryString='SELECT KEY FROM DKR WHERE KEY_ID ="{0}"'.format(Aoldkid)
                    try:
                        rows=usrmng.dbm.executeQuery(queryString)
                    except:
                        print "newDKAss ERROR"
                        Ulogger.info("method: newDKAss - old key value not found")
                        return
                    # this symmetric key must be kept as is, encoded in b64
                    oldskey=rows[0][0]
                    oldskey=b64decode(oldskey)
    #                print "Key of len "+str(len(oldskey))+" has been retrieved: "+str(oldskey)
#                    kid_test,key_test=usrmng.getKey('Private')
                    AEsDtok=crypto.decrypt_AES(str(AEsDtok), str(oldskey),IV)
    			#AEsDtok in plaintext and readable format
                AEsDtok=pickle.loads(b64decode(AEsDtok))
    			#update the counter
    #            AEsDtok[2]=AEsDtok[2]+1
    
    #            print "re-encrypting album:"+ str(AEsDtok[3][2])
    			#Again in b64
    #            AEsDtok=b64encode(pickle.dumps(AEsDtok, pickle.HIGHEST_PROTOCOL))
    			
    			
    			#is there a key associated to all the selected badges and nothing else?
                if badgesKey.has_key(tuple(newSett)):
                    newKid=badgesKey[tuple(newSett)]
                    Ulogger.info("newDKAss: key for badges "+str(newSett)+"already exists: "+ str(newKid))
                    if newKid!=0:
                        queryString='SELECT KEY FROM DKR WHERE KEY_ID ="{0}"'.format(newKid)
                        try:
                            rows=usrmng.dbm.executeQuery(queryString)
                        except:
                            print "newDKAss ERROR"
                            Ulogger.info("method: newDKAss - new key value not found")
                            return
    					#should be kept in b64
                        newKval_enc=str(rows[0][0])
                        newKval=b64decode(newKval_enc)
    #                print "retrieved KLEN is "+str(len(newKval))
    				#TODO 3: update the data
    				# encrypt the album data with the new key
                    fc=usrmng.dbm.findMaxDEK()+1
                    AEsDtok[1]=fc
                    AEsDtok[2]=newKid
                    AEsDtok_d=b64encode(pickle.dumps(AEsDtok, pickle.HIGHEST_PROTOCOL))
                    try:
                        if newKid!=0:
    					    # output will be again in base 64
                            AEsDtok=crypto.encrypt_AES(AEsDtok_d, newKval,IV)
                            #=#####################################################################test
                            #for index in range(3):
                            #    foo=crypto.decrypt_AES(AEsDtok, newKval, iv)
                            #    print "=========================> decryption test for Album "+ str(pickle.loads(b64decode(foo))[3][2])
                            #=######################################################################
                        else:
                            AEsDtok=AEsDtok_d
                    except:
                        Ulogger.info("method: showAlbum - Encryption Error")
                        print traceback.print_exc()
                    #newKval=b64encode(newKval)
                    
                else:
    				#TODO 1: generate a new key
                    newKid=random.randint(1,sys.maxint)
                    newKval=crypto.genRandomKey(AESKLEN)
    #                print "generated KLEN is "+str(len(newKval))
                    # insert new key id and val in DKR
                    usrmng.dbm.addUpdateDKR(newKid,b64encode(newKval))
    				
                    dotest=0				
                    badgesKey[tuple(newSett)]=newKid
                    Ulogger.info("newDKAss: new key "+str(newKid)+"has been added to badges"+str(newSett))
    				
    				#TODO 2: update the badges-key information
    				#add the new keyid in all the badges set by the user with several insertions in BKR
                    for bid in newSett:
                        Ulogger.info("newDKAss: associating badge "+str(bid)+" with key"+str(newKid))
                        usrmng.dbm.addUpdateBKR(bid,newKid)
    
    				#TODO 3: update the data
    				# encrypt the album data with the new key
                    
                    fc=usrmng.dbm.findMaxDEK()+1
                    AEsDtok[1]=fc
                    AEsDtok[2]=newKid
                    AEsDtok_d=b64encode(pickle.dumps(AEsDtok, pickle.HIGHEST_PROTOCOL))
                    try:
                        AEsDtok=crypto.encrypt_AES(AEsDtok_d, newKval, IV)
                        #=#############################################            
                        #dotest=1
                        #for index in range(3):
                        #    foo=crypto.decrypt_AES(AEsDtok, newKval, iv)
                        #    print "=========================>1: immediate decryption test without DB retr" +str(index)+ " for Album "+ str(pickle.loads(b64decode(foo))[3][2])
                        #foo2=crypto.decrypt_AES(AEsDtok, newKval, iv)
                        #foo3=crypto.decrypt_AES(AEsDtok, newKval, iv)
                        #foo4=crypto.decrypt_AES(AEsDtok, newKval, iv)
                        #=#############################################            
            
                        Ulogger.info("newDKAss: album data has been encrypted with new key"+str(b64encode(newKval)))
                        #newKval=b64encode(newKval)			        
                    except:
                        Ulogger.info("method: new key inserted - Encryption Error")
                        print traceback.print_exc()
                    
    					
    				#distribute the new key to friends holding all the selected badges
                    usrmng.publishKey(newKid, newSett)
    			#=#############################################
                #if dotest==1:
                #    newKval=b64decode(newKval)
                #    foo5=crypto.decrypt_AES(AEsDtok, newKval, iv)
                #    print "=========================>2: decryption test without DB retr before DB insertion"
                #    newKval=b64encode(newKval)
                #    newKval=b64decode(newKval)
                #    foo5=crypto.decrypt_AES(AEsDtok, newKval, iv)
                #    print "=========================>2bis: decryption test without DB retr before DB insertion"
                #    newKval=b64encode(newKval)
    			#=#############################################
    			
                # store the new association between DID and KID in DEK
                
                item=[Adid,fc,newKid,AEsDtok]
                dispatcher.mat.add(Job("R_MAT_PRS", item))
                
                usrmng.dbm.addUpdateDEK(form["aid"].value,"ALB",newKid,fc,AEsDtok)
                Ulogger.info("newDKAss: new AesDtok inserted in DEK: "+str(AEsDtok_d))
    			
    			#=#############################################    
                #if dotest==1:
                #    # current version of data
                #    testString='SELECT * FROM DEK WHERE Type="ALB" AND DID="{0}"'.format(form["aid"].value)
                #    testKString='SELECT KEY FROM DKR WHERE KEY_ID ="{0}"'.format(newKid)
                #    rows=usrmng.dbm.executeQuery(testString)
                #    krows=usrmng.dbm.executeQuery(testKString)
                #    testEtok=rows[0][4]
                #    testk=krows[0][0]
    		    #		
                #    newKval=b64decode(newKval)
                #    testk=b64decode(testk)
    				
                #    foo6=crypto.decrypt_AES(AEsDtok, newKval, iv)
                #    print "=========================>3: decryption test without DB retr for Album "+ str(pickle.loads(b64decode(foo))[3][2])
                #    print "\n   retrieved record is equal to the inserted one: "+str(testEtok==AEsDtok)
                #    print "\n   retrieved key is equal to the inserted one: "+str(b64encode(testk)==b64encode(newKval))
                #    testEtok=crypto.decrypt_AES(testEtok, testk, iv)
                #    print "=========================>4: decryption test wtith DB retr for Album "+ str(pickle.loads(b64decode(testEtok))[3][2])
                    #newKval=b64encode(newKval)
                #=#############################################
                
    			#=========================================================================================================================================================================
                # encrypt all the pictures belonging to this album
                queryString='SELECT * FROM DEK WHERE Type="PCT" AND DID IN (SELECT ID FROM PCT WHERE aid="'+form["aid"].value+'")'
                try:
                    rows=usrmng.dbm.executeQuery(queryString)
                except:
                    print "newDKAss ERROR"
                    Ulogger.info("method: newDKAss - unable to list pictures in DEK")
                    return
                for row in rows:
    			    # PEsDtok is already in B64
                    Pdid, Ptype, Poldkid, PoldCounter, PEsDtok=row
    #                print "Ptype is: "+str(Ptype)
                    if PoldCounter==None:
                        PoldCounter=0
                    if Poldkid!=0:
                        PEsDtok=crypto.decrypt_AES(str(PEsDtok), str(oldskey),IV)
    #                print "pesdtok len: "+str(len(PEsDtok))
                    PEsDtok=b64decode(PEsDtok)
                    PEsDtok=pickle.loads(str(PEsDtok))
                    fc=usrmng.dbm.findMaxDEK()+1
                    PEsDtok[1]=fc
                    PEsDtok[2]=newKid
    #                print "re-encrypting picture "+PEsDtok[3][7]
                    PEsDtok=b64encode(pickle.dumps(PEsDtok, pickle.HIGHEST_PROTOCOL))
                    if newKid!=0:
                        PEsDtok=crypto.encrypt_AES(PEsDtok, newKval,IV)
                    # store the new association between DID and KID in DEK
                    usrmng.dbm.addUpdateDEK(Pdid,"PCT",newKid,fc,PEsDtok)
                    item=[Pdid,fc,newKid,PEsDtok]
                    dispatcher.mat.add(Job("R_MAT_PRS", item))
                   
    			
    			# TODO : send PRS request to mirrors, they should overwrite the existing information they actually store in their FDR
                
    
    
            else:
                pass
                
            
    		
            realfile = './web/gallery.html'
            f = open(realfile, "r")
            global openpageid
            openpageid = guid
            pag = f.read()
            pag = pag.replace("targetUID",guid)   # replace the string "targetUID" in the podium.html with the requested id_number
                                                                # in this way, the ajax script will know the owner id of the podium
                                                                # and will ask with req["podium"] the proper data (req["id"])
            #self.send_header('Content-type', 'text/html')
            #self.end_headers()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(pag)
            f.close()
            return
        except:
            print 'Error in Do_Post'
            print traceback.print_exc()
            pass
    
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


class DataManager():
        
    def __init__(self, dbFileName):
        self._db = sqlite3.connect(dbFileName,check_same_thread=False)  # "check_same_thread=False" if true throws an exception 
                                                                        # whenever a thread different from the creator thread of the db access data
                                                                        # (you can use locks...)
        self._db.isolation_level = None
        self._db.text_factory = str
        self._cursor = self._db.cursor()
        self.l = threading.Lock()
        
    def executeQuery(self, query):
        # execute a general full customized SQL query
        self.l.acquire()
        try:
            self._cursor.execute(query)
            rows = self._cursor.fetchall()
        except:
            print 'error in execute query'
            print query
            self.l.release()
            print traceback.print_exc()
            return []
        self.l.release()
        return rows        
    
    def updateDKR(self,keyid,bid,type,sKey):
        self.l.acquire()
        try:    
            self._cursor.execute("SELECT KEY FROM DKR WHERE KEY_ID=:keyid", {'keyid':keyid})
            if self._cursor.fetchone() == None:#add new row
                self._cursor.execute('INSERT INTO DKR(bid,type,key) VALUES (?, ?, ?)', (bid, type, sKey))
            else:
                self._cursor.execute('UPDATE DKR SET bid=?, type=?, key=? WHERE Key_ID=?', (bid, type, sKey,keyid))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
		
    def addUpdateDKR(self,keyid,sKey):
        self.l.acquire()
        try:
            self._cursor.execute("SELECT KEY FROM DKR WHERE KEY_ID=:keyid", {'keyid':keyid})
            if self._cursor.fetchone() == None:#add new row
#                print "inserting a new key whose len is "+str(len(sKey))+ " and value is "+sKey
                self._cursor.execute('INSERT INTO DKR(KEY_ID, KEY) VALUES (?, ?)', (keyid, sKey))
            else:
                self._cursor.execute('UPDATE DKR SET KEY=? WHERE KEY_ID=?', (sKey,keyid))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()

    def getBID(self, badgeName):
        self.l.acquire()
        try:
            self._cursor.execute("SELECT BID FROM BDG WHERE BadgeName=:badgeName", {'badgeName': badgeName})
            a=self._cursor.fetchone()
            if a == None:
                bid=-1
            else:
                bid=a[0]
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return -1
        self.l.release()
        return bid
    def getBadge(self, bid):
        self.l.acquire()
        try:
            self._cursor.execute("SELECT BadgeName FROM BDG WHERE BID=:bid", {'bid': bid})
            a=self._cursor.fetchone()
            if a == None:
                bn=-1
            else:
                bn=a[0]
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return -1
        self.l.release()
        return bn
    def addBDG(self,badgeName,bid=None):
        # add Badge
        self.l.acquire()
        try:
            self._cursor.execute("SELECT BID FROM BDG WHERE BadgeName=:badgeName", {'badgeName': badgeName})
            a=self._cursor.fetchone()
            if a == None:
                if bid==None:
                    while (True):
                        bid=random.randrange(1,999999999)
                        self._cursor.execute("SELECT BadgeName FROM BDG WHERE BID=:bid", {'bid': str(bid)})
                        if self._cursor.fetchone() == None:
                            break
                self._cursor.execute('INSERT INTO BDG(BID,BadgeName) VALUES (?,?)', (bid,badgeName))
            else:
                bid=a[0]
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return -1
        self.l.release()
        return bid
    
    def addUpdateAlbum(self,uidOwner,name,idthumb,aid=None):
        self.l.acquire()
        try:
            self._cursor.execute("SELECT * FROM ALB WHERE AID=:aid AND UIDowner=:uidowner", {'aid': str(aid), 'uidowner':uidOwner})
            if self._cursor.fetchone() == None:
                if aid==None:
                    while (True):
                        aid=random.randint(1,sys.maxint)
                        self._cursor.execute("SELECT * FROM ALB WHERE AID=:aid AND UIDowner=:uidowner", {'aid': aid, 'uidowner':uidOwner})
                        if self._cursor.fetchone() == None:
                            break
                self._cursor.execute('INSERT INTO ALB(aid, aname, uidowner, IDTHUMB) VALUES (?,?,?,?)', (aid, name, uidOwner, idthumb))
                #self._cursor.execute('SELECT last_insert_rowid()')
            else:
                self._cursor.execute('UPDATE ALB SET Aname =?, IDTHUMB=? WHERE AID=?', (name,idthumb,aid))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
        
        return aid
    #@debug
    def addUpdateDEK(self,did,type,kid,counter,esdtok):
        # add / update Data - Encryption key relationship
        self.l.acquire()
        try:
            self._cursor.execute("SELECT * FROM DEK WHERE DID=:did AND TYPE=:type", {'did': did, 'type':type})
            if self._cursor.fetchone() == None:
                Ulogger.info("inserting new record in dek")
                self._cursor.execute('INSERT INTO DEK(did, type, key_id, fcount, my_esdt) VALUES (?,?,?,?,?)', (did, type, kid, counter, esdtok))
            else:
                Ulogger.info("updating existing record in dek")
                self._cursor.execute('UPDATE DEK SET KEY_ID=?, fcount=?, my_esdt=? WHERE DID=? AND Type=?', (kid, counter, esdtok, did, type))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
        
    def addUpdateBKR(self,bid,kid):
        # add / update Data - Encryption key relationship
        self.l.acquire()
        try:
            self._cursor.execute("SELECT * FROM BKR WHERE BID=:bid AND KEY_ID=:kid", {'bid': bid, 'kid':kid})
            if self._cursor.fetchone() == None:
                Ulogger.info("inserting new record in BKR")
                self._cursor.execute('INSERT INTO BKR(BID,KEY_ID) VALUES (?, ?)', (bid,kid))
            else:
                Ulogger.info("record in BKR already exists")
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
    def getkeyDKR(self,kid):
        self.l.acquire()
        try:
            self._cursor.execute("SELECT KEY FROM DKR WHERE KEY_ID=:kid", {'kid': str(kid)})
            a=self._cursor.fetchone()
            if a==None:
                key=-1
            else:
                key=a[0]
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return -1
        self.l.release()
        return b64decode(key)

    def addDKR(self,sKey,kid=None):
        # add Data Keys Repository
        sKey=b64encode(sKey)
        self.l.acquire()
        try:
            if kid==None:
                while (True):
                    kid=random.randrange(1,999999999)
                    self._cursor.execute("SELECT KEY FROM DKR WHERE KEY_ID=:kid", {'kid': str(kid)})
                    if self._cursor.fetchone() == None:
                        break
            else:
                self._cursor.execute("SELECT Key FROM DKR WHERE Key_ID=:kid", {'kid':str(kid)})
                if self._cursor.fetchone()!=None:
                    self.l.release()
                    print 'kid already Exist'
                    return kid
            self._cursor.execute('INSERT INTO DKR(KEY_ID,KEY) VALUES (?, ?)', (kid, sKey))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return -1
        self.l.release()
        return kid
    def addACP(self,uid,bid):
        self.l.acquire()
        try:
            self._cursor.execute("SELECT BID FROM ACP WHERE UIDOWNER=:uid AND BID=:bid", {'uid':uid,'bid': bid})
            if self._cursor.fetchone()==None:
                self._cursor.execute('INSERT INTO ACP(UIDOWNER,BID) VALUES (?, ?)', (uid,bid))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
    def getACPList(self,bid):
        self.l.acquire()
        try:
            self._cursor.execute("SELECT UIDOWNER FROM ACP WHERE BID=:bid", {'bid': bid})
            a=self._cursor.fetchall()
            if a==None:
                list=[]
            else:
                list=a
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return []
        self.l.release()
        return list
    def checkKey(self,bid):
        
        if bid==0:
            return 0
        self.l.acquire()
        try:
            self._cursor.execute("SELECT KEY_ID FROM BKR WHERE BID=:bid", {'bid': bid})
            a=self._cursor.fetchone()
            if a==None:
                key=-1
            else:
                key=a[0]
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return -1
        self.l.release()
        return key
        
    def addBKR(self,bid, key_id):
        self.l.acquire()
        try:
            self._cursor.execute('INSERT INTO BKR(BID,KEY_ID) VALUES (?, ?)', (bid, key_id))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
    def addDEK(self,did,type,kid,fcount,my_edst):
        # add / update Data Keys Repository
        self.l.acquire()
        try:
            self._cursor.execute("SELECT Key_ID FROM DEK WHERE DID=:did AND TYPE=:type", {'did': did, 'type':type})
            if self._cursor.fetchone() == None:
                self._cursor.execute('INSERT INTO DEK(DID,TYPE,Key_ID,FCOUNT,My_ESDT) VALUES (?, ?, ?, ?,?)', (did,type,kid,fcount,my_edst))
            else:
                self._cursor.execute('UPDATE DEK SET Key_ID=?,FCOUNT=?, My_ESDT=? WHERE DID=? AND TYPE=?', (kid,fcount,my_edst,did,type))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
    def getDEK(self,type,kid):
        self.l.acquire()
        try:
            query="SELECT DID FROM DEK WHERE TYPE='"+type+"' AND Key_ID="+str(kid)      
            self._cursor.execute(query)
            a=self._cursor.fetchall()
            if a==None:
                list=[]
            else:
                list=a
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return []
        self.l.release()
        return list
            
    def delFDR(self,uid):
        self.l.acquire()
        try:
            self._cursor.execute('DELETE FROM FDR WHERE UIDOWNER='+uid)
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
    def addupdateFDR(self,uid,did,fcount,kid,fr_edst):
        # add / update Data Keys Repository
        self.l.acquire()
        try:
            self._cursor.execute("SELECT Key_ID FROM FDR WHERE DID=:did AND UIDOWNER=:uid", {'did': did,'uid':uid})
            if self._cursor.fetchone() == None:
                self._cursor.execute('INSERT INTO FDR(UIDOWNER,Key_ID,DID,FCOUNT,Fr_ESDT) VALUES (?, ?,?, ?,?)', (uid,kid,did,fcount,fr_edst))
            else:
#                print 'updating fdr: '+str(uid)+" : "+str(fcount)
                self._cursor.execute('UPDATE FDR SET FCOUNT=?,Key_ID=?, Fr_ESDT=? WHERE UIDOWNER=? AND DID=?', (fcount,kid,fr_edst,uid,did))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
    def getFDRfromDB(self,uid,did=None):
        self.l.acquire()
        try:
            if did==None:
                self._cursor.execute("SELECT UIDOWNER,DID,FCOUNT,Key_ID,Fr_ESDT FROM FDR WHERE UIDOWNER=:uid", {'uid': uid})
            else:
                self._cursor.execute("SELECT UIDOWNER,DID,FCOUNT,Key_ID,Fr_ESDT FROM FDR WHERE UIDOWNER=:uid AND DID=:did", {'uid': uid,'did':did})
            a=self._cursor.fetchall()
            if a==None:
                rows=[]
            else:
                rows=[]
                rows.append(a)
            self.l.release()
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return []
        return rows
    def isFDR(self,uid):
        self.l.acquire()
        try:
            self._cursor.execute("SELECT * FROM FDR WHERE UIDOWNER=:uid", {'uid': uid})
            a=self._cursor.fetchone()
            if a==None:
                flag=False
            else:
                flag=True
            self.l.release()
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return -1
        return flag

    def addRDR(self,did,uid,type,fcount,kid):
        # add / update Data Keys Repository
        self.l.acquire()
        flag=True
        try:
            self._cursor.execute("SELECT Key_ID FROM RDR WHERE DID=:did AND UIDOWNER=:uid AND type=:type AND FCOUNT=:fc", {'did': int(did),'uid':uid,'type':type,'fc':fcount})
            a=self._cursor.fetchone()
            if a == None:
                print 'Inserting RDR'
                self._cursor.execute('INSERT INTO RDR(DID,UIDOWNER,TYPE,Key_ID,FCOUNT) VALUES (?, ?,?, ?,?)', (int(did),uid,type,kid,fcount))
            else:
                if a[0]<fcount:
                    print 'Updating RDR'
                    self._cursor.execute('UPDATE RDR SET Key_ID=?,FCOUNT=? WHERE DID=? AND UIDOWNER=? AND TYPE=? AND  FCOUNT=?', (kid,fcount,did,uid,type,fcount))
                else:
                    flag=False
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
        return flag
    def getFCountRDR(self,uid):
        self.l.acquire()
        try:
            self._cursor.execute("SELECT FCOUNT FROM RDR WHERE UIDOWNER=:uid", {'uid': uid})
            a=self._cursor.fetchall()
            if a==None:
                list=[]
            else:
                list=a
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return []
        self.l.release()
        return list
            
    def findMaxDEK(self):
        self.l.acquire()
        try:
            self._cursor.execute('SELECT max(FCOUNT) FROM DEK')
            a=self._cursor.fetchone()
            if a[0]==None:
                max=0
            else:
                max=a[0] 
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return -1 
        self.l.release()    
        return int(max)
    def addDDR(self,uid,did,fcount):
        self.l.acquire()
        try:
            self._cursor.execute('INSERT INTO DDR(fcount,DID,UID_SF) VALUES (?, ?,?)', (fcount,did,uid))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
    
       
    def addUpdateFDD(self,uidowner,kid):
        # add / update Data Keys Repository
        self.l.acquire()
        try:
            self._cursor.execute("SELECT UIDOWNER FROM FDD WHERE UIDOWNER=:uid AND Key_ID=:kid", {'uid': uidowner, 'kid':kid})
            if self._cursor.fetchone() == None:
                self._cursor.execute('INSERT INTO FDD(UIDOWNER,Key_ID) VALUES (?, ?)', (uidowner,kid))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
                                
    def addUpdatePost(self, pid,uid, uidowner, content, time_v, istweet, firstid):
        # add / update post (post or tweet)
        self.l.acquire()
        try:
            self._cursor.execute("SELECT id FROM PST WHERE id=:postid AND uid=:userid", {'postid': pid, 'userid':uid})
            if self._cursor.fetchone() == None:
                self._cursor.execute('INSERT INTO PST(uid, id, uidowner, content, time, istweet, firstid) VALUES (?, ?, ?, ?, ?, ?, ?)', (uid, pid, uidowner, content, time_v, istweet, firstid))
            else:
                self._cursor.execute('UPDATE PST SET content=?, istweet=?, uidowner=?, time=?, firstid=? WHERE id=? AND uid=?', (content, istweet, uidowner, time_v, firstid, pid, uid))
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return
        self.l.release()
        
    def addUpdatePPI(self, uidfriend, name, lastname, sex, birthday, birthplace, nationality, mail, fixedtel, mobiletel, company, department, role, companymail, companytel, companymobiletel, avatar):
        # add / update PPI data
        #avatar should be binary data.
        if avatar is None:
            f = open("web"+sep+"img"+sep+constants.default_avatar, 'rb' )
            binaryObject = f.read()
            f.close()
            avatar = b64encode(sqlite3.Binary(binaryObject))
        self.l.acquire()    
        self._cursor.execute("SELECT * FROM PPI WHERE uidfriend=:userid", {'userid':uidfriend})
        if self._cursor.fetchone() is not None:
            self._cursor.execute("DELETE FROM PPI WHERE uidfriend=:userid", {'userid':uidfriend})
        
        self._cursor.execute('INSERT INTO PPI( UIDFRIEND, NAME, LASTNAME, SEX, BIRTHDAY, BIRTHPLACE, NATIONALITY, MAIL, FIXEDTEL, MOBILETEL, COMPANY, DEPARTMENT, ROLE, COMPANYMAIL, COMPANYTEL, COMPANYMOBILETEL, AVATAR) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (uidfriend, name, lastname, sex, birthday, birthplace, nationality, mail, fixedtel, mobiletel, company, department, role, companymail, companytel, companymobiletel, str(avatar)))
        self.l.release()
        
    def deletePost(self):
        pass
    
    def retrieveAllColumns(self, table, uid):
        self.l.acquire()
        self._cursor.execute('SELECT * FROM %s WHERE uidfriend=:userid'% table, {'userid':uid})
        a = self._cursor.fetchone()
        self.l.release()
        return a
        
    def retrieve(self, table, column, uid, pid=None):
        # retrieve "column" from "table" with "userid" and "postid"
        if table=="PST":
            self.l.acquire()
            self._cursor.execute('SELECT %s FROM PST WHERE id=:postid AND uid=:userid'% column, {'postid': pid, 'userid':uid})
            row = self._cursor.fetchone()
            self.l.release()
            if row is None:
                return None
            else:
                return str(row[0])  
        elif table=="PCT":
            self.l.acquire()
            self._cursor.execute('SELECT %s FROM PCT WHERE id=:postid AND uid=:userid'% column, {'postid': pid, 'userid':uid})
            row = self._cursor.fetchone()
            self.l.release()
            if row is None:
                return None
            else:
                return pickle.loads(str(row[0]))
        elif table=="PPI":
            self.l.acquire()
            self._cursor.execute('SELECT %s FROM PPI WHERE uidfriend=:userid'% column, {'userid':uid})
            row = self._cursor.fetchone()
            self.l.release()
            if row is None:
                return None
            else:
                if column=="avatar":
                    return cStringIO.StringIO(b64decode(row[0])).getvalue()
                else:
                    return str(row[0])
            
    def retrieveMany(self, table, exclude=None):
        # retrieve many records from a table (now only PPI) excluding those with a certain userid
        # (used for contacts page)
        if table=="PPI":
            self.l.acquire()
            self._cursor.execute('SELECT * FROM PPI WHERE uidfriend <> \'' + exclude + '\'')
            rows = self._cursor.fetchall()
            self.l.release()
            return rows
    
    def storedDataToString(self, table):
        # DEBUG
        self.l.acquire()
        self._cursor.execute("SELECT * FROM %s"% table)
        rows = self._cursor.fetchall()
        self.l.release()
        retStr=""
        if table=="PST":
            for row in rows:
                retStr+= row[0] + " - " + row[1] + " - " + row[2] + " - " + str(row[3]) + "\n"
        elif table=="PCT":
            for row in rows:
                retStr+= row[0] + " - " + row[1] + " - " + row[2] + " - " + "PICTURE" + " - " + row[4] + "\n"
        elif table=="PPI":
            for row in rows:
                retStr+= row[0] + " - " + row[1] + " - " + row[2] + " - " + row[3] + " - " + "PICTURE" + "\n"
        return retStr

    def addUpdatePicture(self,uidowner,time_v,aidowner,width,height,filetype,filename,filedata, filedesc, id=None):
        # add/update picture in PCT
        #idownerTemp=self.executeQuery("SELECT COUNT(ID) from PCT")
        self.l.acquire()
        try:
            self._cursor.execute("SELECT id FROM PCT WHERE UIDOWNER=:uidowner AND ID=:id", {'uidowner': uidowner, 'id':id})
            if self._cursor.fetchone() == None:
                if id==None:
                    while (True):
                        id=random.randrange(1,999999999)
                        self._cursor.execute("SELECT id FROM PCT WHERE ID=:id AND UIDOWNER=:uidowner", {'id': str(id), 'uidowner':uidowner})
                        if self._cursor.fetchone() == None:
                            break
                    self._cursor.execute('INSERT INTO PCT(id,uidowner, time, aid,width,height,filetype,filename,filedata, filedesc) VALUES (?,?, ?,?, ?, ?, ?,?, ?,?)', (str(id),uidowner, time_v, aidowner,width,height,filetype,filename,filedata, filedesc))
                else:
                    self._cursor.execute('INSERT INTO PCT(id, uidowner, time, aid,width,height,filetype,filename,filedata, filedesc) VALUES (?,?, ?,?, ?, ?, ?,?, ?,?)', (id,uidowner, time_v, aidowner,width,height,filetype,filename,filedata, filedesc))
                self._cursor.execute('SELECT last_insert_rowid()')
                #pid=self._cursor.fetchone()
            else:
                    self._cursor.execute('UPDATE PCT SET uidowner=?, time=?, aid=?,width=?,height=?,filetype=?,filename=?,filedata=?, filedesc=? WHERE id=?', (uidowner,time_v, aidowner,width,height,filetype,filename,filedata, filedesc, id))
            self._db.commit()
        except:
            print 'error in execute query'
            self.l.release()
            print traceback.print_exc()
            return -1
        self.l.release()
        return id
    
    def save_objects(self, name, data):
        self.l.acquire()
        self._cursor.execute("DELETE FROM " + name + " WHERE id=1")
        self._cursor.execute("INSERT INTO " + name + "(id, data) VALUES (1, ?)", (buffer(pickle.dumps(data, pickle.HIGHEST_PROTOCOL)),))
        self._db.commit()
        self.l.release()
        return

    def load_objects(self, name):
        
        self.l.acquire()
        self._cursor.execute("SELECT data FROM " + name + " WHERE id=1")
        row = self._cursor.fetchone()
        self.l.release()
        if row is not None:
            return pickle.loads(b64decode(row[0]))
#            return pickle.loads(str(row[0]))
        else:
            return None
    
    def addToFAT(self, id, data):
        try:
            self.l.acquire()
            self._cursor.execute("INSERT INTO FAT (id, data) VALUES (?, ?)", (id, buffer(pickle.dumps(data, pickle.HIGHEST_PROTOCOL))))
            self.l.release()
            return True
        except:
            return False

    def popFAT(self, id):
        self.l.acquire()
        query = "SELECT data FROM FAT WHERE id='" + id + "'" 
        self._cursor.execute(query)
        result_l = self._cursor.fetchall()
        list = []
        for x in result_l:
            list += pickle.loads( str(x[0])  )
            print "eeee"+str(x[0])
        self._cursor.execute("DELETE FROM FAT WHERE id='"+id+"'")
        self.l.release()
        return list

        