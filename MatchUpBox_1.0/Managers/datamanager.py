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

import constants
import sqlite3
from base64 import b64encode, b64decode

tableNames = ['PCT', 'ALB', 'PST', 'PPI', 'DDR', 'FDR', 'FAT', 'FDD', 'DKR', 'BDG','ACP', 'DEK','RDR']
tableGenerationQuery = '''
CREATE TABLE PCT(
   ID INTEGER NOT NULL ,
   UIDOWNER TEXT NOT NULL,
   TIME TEXT,
   AID INTEGER,
   WIDTH INTEGER,
   HEIGHT INTEGER,
   FILETYPE TEXT,
   FILENAME TEXT,
   FILEDATA TEXT,
   FILEDESC TEXT,
   PRIMARY KEY (ID, UIDOWNER)
);

CREATE TABLE ALB(
   AID INTEGER NOT NULL,
   UIDOWNER INTEGER,
   ANAME TEXT,
   IDTHUMB INTEGER,
   PRIMARY KEY (AID,UIDOWNER)
);

CREATE TABLE PST(
    ID TEXT   PRIMARY KEY,
    UID TEXT  ,
    UIDOWNER TEXT  ,
    CONTENT TEXT,
    TIME TEXT,
    FIRSTID TEXT,
    ISTWEET INTEGER,
    FOREIGN KEY (FIRSTID) REFERENCES PST(ID)
);

CREATE TABLE PPI(
    UIDFRIEND TEXT   PRIMARY KEY,
    NAME TEXT,
    LASTNAME TEXT,
    SEX TEXT,
    BIRTHDAY TEXT,
    BIRTHPLACE TEXT,
    NATIONALITY TEXT,
    MAIL TEXT,
    FIXEDTEL TEXT,
    MOBILETEL TEXT,
    COMPANY TEXT,
    DEPARTMENT TEXT,
    ROLE TEXT,
    COMPANYMAIL TEXT,
    COMPANYTEL TEXT,
    COMPANYMOBILETEL TEXT,
    AVATAR BLOB
);

CREATE TABLE DDR(
    FCOUNT INTEGER  ,
    DID INTEGER,
    UID_SF TEXT
);

CREATE TABLE FDR(
    UIDOWNER TEXT  ,
    DID INTEGER,
    FCOUNT INTEGER,
    Key_ID INTEGER,
    Fr_ESDT BLOB
);

CREATE TABLE FAT(
    id TEXT   ,
    data BLOB,
    PRIMARY KEY (id, data)
);

CREATE TABLE FDD(
    UIDOWNER TEXT  ,
    KEY_ID INTEGER
);

CREATE TABLE DKR(
    KEY_ID INTEGER PRIMARY KEY AUTOINCREMENT,
    KEY TEXT
);
CREATE TABLE BDG(
    BID INTEGER PRIMARY KEY,
    BadgeName TEXT
);
CREATE TABLE BKR(
    BID INTEGER  ,
    KEY_ID INTEGER
);
CREATE TABLE ACP(
    UIDOWNER TEXT,
    BID INTEGER
);
CREATE TABLE DEK(
    DID INTEGER,
    TYPE TEXT,
    Key_ID INTEGER,
    FCOUNT INTEGER,
    My_ESDT BLOB
);
CREATE TABLE RDR(
    DID INTEGER,
    UIDOWNER TEXT,
    TYPE TEXT,
    Key_ID INTEGER,
    FCOUNT INTEGER
);
CREATE TABLE AAA(
    id INTEGER   PRIMARY KEY,
    data BLOB
);

CREATE TABLE BBB(
    id INTEGER   PRIMARY KEY,
    data BLOB
);
'''
def createDatabase(uid):
    db_filename = constants.databaseNamePrefix + uid + constants.databaseNameExtension

    conn = sqlite3.connect(db_filename)
    c = conn.cursor()
    def dropTables(tableName):
        try:
            c.execute('DROP TABLE ' + tableName)
        except:
            print 'no table to drop for table name:', tableName, 'in database', db_filename
    #for name in tableNames:
    #    dropTables(name)
    c.executescript(tableGenerationQuery)
    conn.commit()
    c.close()
    conn.close()
def coverAsString(input):
    return '\'' + input + '\''
           
def addPPIEntry(uid, ppiTuple, avatarFileName):
    'adds ppiTuple to corresponding database'
    values = "'"+str(uid)+"', "
    for entry in ppiTuple:
        if entry == ppiTuple[len(ppiTuple) - 1]:
            values += coverAsString(entry)
        else:
            values += coverAsString(entry) + ', '
    values += ', ?)'
    #ppiInsertionQuery = 'INSERT INTO PPI( UIDFRIEND, NAME, LASTNAME, SEX, BIRTHDAY, BIRTHPLACE, NATIONALITY, MAIL, FIXEDTEL, MOBILETEL, COMPANY, DEPARTMENT, ROLE, COMPANYMAIL, COMPANYTEL, COMPANYMOBILETEL, AVATAR) VALUES (' + values
    ppiInsertionQuery = 'INSERT INTO PPI( UIDFRIEND, NAME, LASTNAME, SEX, BIRTHDAY, BIRTHPLACE, NATIONALITY, AVATAR) VALUES (' + values
    #print ppiInsertionQuery
    db_filename = constants.databaseNamePrefix + uid + constants.databaseNameExtension
    #db_filename2 = constants. + ppiTuple[0] + constants.databaseNameExtension
    conn = sqlite3.connect(db_filename)
    #conn2 = sqlite3.connect(db_filename2)
    conn.isolation_level = None
    #conn2.isolation_level = None
    c = conn.cursor()
    #c2 = conn2.cursor()
    #avatarFileName = avatarPrefix + str(avatarnumber) + avatarExtension
    #if debug:
    #    print 'avatar file:', avatarFileName
    
    f = open(avatarFileName, 'rb' )
    binaryObject = f.read()
    f.close()
    
    c.execute(ppiInsertionQuery,[str(b64encode(sqlite3.Binary(binaryObject)))])    

    conn.commit()
    c.close()
    conn.close()

def selection(uid):
    db_filename = constants.databaseNamePrefix + uid + constants.databaseNameExtension
    #db_filename2 = constants. + ppiTuple[0] + constants.databaseNameExtension
    conn = sqlite3.connect(db_filename)
    #conn2 = sqlite3.connect(db_filename2)
    conn.isolation_level = None
    #conn2.isolation_level = None
    c = conn.cursor()
    
    c.execute("select * from PPI ")
    #print "HELLO"
    #print c.fetchone()
    c.close()
    conn.close()