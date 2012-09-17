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
import time, os, hashlib
from constants import uid_filename
import types
import Managers.crypto as crypto
import binascii
import cPickle as pickle
import traceback
#added by andrea
import re
import datetime

def retrieveUid2(num):
    #uid restore process starts here
    uid_file = open(uid_filename, 'r')
    uid = -1
    counter = 1
    for line in uid_file.readlines():
        if counter == num:
            uid = line.split('\n')[0]
        counter += 1
    uid_file.close()
    if uid == -1:
        print 'no uid assigned for this user in the initialization script'
        time.sleep(2)
        os._exit(1)
    else:
        return uid



#added from andrea
def retrive_K(file):
    try:
        f=open(file,"r")
        k=f.read()
    except:
        return False
    return k

def checkCertificate(cert,keyPublic=crypto.loadPublicKey("TIS")):
    
    if cert.__len__()!=3:
       logging.error("Invalid certificate, (Data,PublicKey,Signature)")
       return False
    if not (crypto.verify_sign(keyPublic,(cert[0]+cert[1]),cert[2])):
        logging.error("Signature into certificate not verified")# check this!!!!!
        return False#check this!!!!

    return True
    
def checkUid():
        try:
            f=open(uid_filename,"r")
        except IOError, msg:
            #logging.error("Unable to open UID: %s"%(msg))
            return False
        uid=f.readline().strip("\n")
        f.close()
        try:
            f=open("mypem"+os.sep+uid+"_U_Keys.pem","r")
        except IOError:
            return False
        f.close()
        return True
# creator andrea
def my_check_port(string):
    if not string.isdigit():
        return False
    if len(string)<=0:
        return False
    if len(string)>6:
        return False
    if int(string)<=0:
        return False
    if int(string)>65535:
        return False
    return True
    
def my_check_str(string):
        if re.match('^[a-zA-Z]{1,20}$',str(string))== None:
            return False
        return True
def my_check_sex(string):
    if not (str(string).lower() == "male" or str(string).lower() == "female"):
            return False
    return True
def my_check_date(string):
    if(len(string)<10):
        return False
    try:
        d = datetime.date(int(str(string).split('/')[2]),int(str(string).split('/')[1]),int(str(string).split('/')[0]))
    except ValueError:
        return False
    if (d < datetime.date(1900,1,1) or d > datetime.date.today()):
        return False
    return True
def my_check_nation(string):
    if re.match('^[a-z]{1,3}$',str(string))== None:
        return False
    return True
def getUid():
    try:
        f=open(uid_filename,"r")
    except IOError, msg:
            #logging.error("Unable to open UID: %s"%(msg))
        return False
    uid=f.readline()
    f.close()
    return uid.strip("\n").strip(" ")

def retrieveUid():
    #uid restore process starts here
    uid_file = open(uid_filename, 'r')
    uid=uid_file.readline().strip()
    #uid = -1
    #counter = 1
    #for line in uid_file.readlines():
    #    if counter == num:
    #        uid = line.split('\n')[0]
    #    counter += 1
    #uid_file.close()
    #if uid == -1:
    #    print 'no uid assigned for this user in the initialization script'
    #    time.sleep(2)
    #    os._exit(1)
    #else:
    return uid

def getCombinations(input):
    input.strip().lower()
    ls = input.split(" ")
    result = []
    for elm in ls:
        for elm2 in ls:
            if elm != elm2:
                result += [elm + elm2]
        result += [elm]
    return result

def determineTypes(input):
    if type(input) == types.ListType or type(input) == types.TupleType or type(input) == types.DictType:
        print '(', #str(type(input)).split("'")[1].split("'"), ':',
        for elm, i in zip(input, range(len(input))):
            determineTypes(elm)
            if i != len(input) - 1:
                print ',',
        print ')',
    else:
        print str(type(input)).split("'")[1].split("'"),

def verifyPropertiesList(propList, uPKey, signature):
    #if crypto.verify_sign(propList[0][1][1], pickle.dumps(propList, pickle.HIGHEST_PROTOCOL), signature):
    #    print 'Data is signed with the corresponding user id private key'
    #else:
    #    print 'Data is not signed with the corresponding user id private key'
    try:
        propListToVerify = propList[0:2] + [[propList[3][0].split('/')[2], propList[3][1]]] + propList[4:6]
        
        verification = True
        names = ['name', 'surname', 'birth year', 'birth place', 'nationality']
        message = ''    
        counter = 0
        for elm in propListToVerify:
            if uPKey != elm[1][1]:
                message += 'Public key in the certificate is not correct!\n'
                verification = False 
            if hashlib.sha1(elm[0].lower()).digest() == elm[1][0]:
                if not crypto.verify_tis_cert(elm[1]):
                    message += '->property '+str(elm[0].lower())+' is not valid\n'
                    #message += names[counter] + ' certificate is not valid!\n'
                    verification = False
                else:
                    message += '->property '+str(elm[0].lower())+' is valid\n'
                    #message += names[counter] + ' certificate is valid!\n'
            else:
                message += str(elm[0].lower())+' hashes do not match!\n'
                #message += names[counter] + ' hashes do not match!\n'
                verification = False
            counter += 1
        print message
        return verification
    except:
        return False

def bor_verifyPropertiesList(propList, uPKey):
    """
        list of properties = name, surname, sex, birth date, birthplace,nationality, plus other non certificate properties (eg. phone number, email ...)
        for each property
        propList = [ property, Certificate ] 
        Certificate = (h(property),uid_public_key, signtis_private )
    """
    try:
        #check the length , at least 6 necessary fields
        if len(propList) < 6:
            #print "Invalid property List len" 
            return False
        
        #for safety reason it's the only element accessed before the check for getting rid of the date, see next comment
        if len(propList[3]) != 2:
            #print ("Invalid property List len element 3")
            return False
        
        #getting rid of the sex , and getting rid of the date keeping only the year [ '01/02/1993', (h(1993), u_public, sign)] --> [ '1993', (h(1993), u_public, sign)]
#        for p in propList:
#            print p[0]
        propListToVerify = propList[0:2] + [[propList[3][0].split('/')[2], propList[3][1]]] + propList[4:6]
        
        verification = True
        names = ['name', 'surname', 'birth year', 'birth place', 'nationality']
        message = ''    
        counter = 0
        
        for x in propListToVerify:
            #checking the element of the list len [property, certificate]
            if len(x) != 2:
                #print ("invalid len in propertylist")
                return False
            prop,cert=x
            
            #checking the cert len (h(property), u_p, sign)
            if len(cert) != 3:
                #print ("invalid len in propertylist certificate")
                return False
            hash,u_p,sign = cert
            
            #checking the user public key with the user public key in the certificate
            if uPKey != u_p:
                message += 'Public key in the certificate is not correct!\n'
                verification = False 
            
            #checking the hash of the property    
            if hashlib.sha1(prop.lower()).digest() != hash:
                message += names[counter] + ' hashes do not match!\n'
                verification = False
            
            #checking the certificate signature 
            if not crypto.verify_tis_sign(hash+u_p,sign):
                message += names[counter] + ' certificate is not valid!\n'
                verification = False
            counter += 1
            
        #logging.debug(message)
        return verification
    except:
        print traceback.print_exc()
        return False