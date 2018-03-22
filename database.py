import sqlite3
from macros import AESKEYSIZE, RSAKEYSIZE, EntityNameMaxLen, GroupNameMaxLen
from logger import logger as log
from inspect import currentframe

file = currentframe()
DatabaseFile = "authDB.db"

def createTables():
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    # Create Group table
    try:
        c.execute('''
                  CREATE TABLE GroupTable(
                  GroupName VARCHAR(%d), 
                  ValPeriod float NOT NULL,
                  PRIMARY KEY (GroupName)
                  )''' % GroupNameMaxLen)
    except Exception as e:
        print(e)

    # Create Entity table
    try:
        c.execute('''
                  CREATE TABLE EntityTable(
                  EntityName VARCHAR(%d),
                  GroupName VARCHAR(%d),
                  PublicKey BINARY(%d) NOT NULL, 
                  DistKey BINARY(%d) NOT NULL, 
                  ValidUntil float NOT NULL,
                  ip VARCHAR(15) NOT NULL,
                  port INTEGER NOT NULL,
                  PRIMARY KEY (EntityName)
                  )''' % (EntityNameMaxLen, GroupNameMaxLen, RSAKEYSIZE, AESKEYSIZE))
    except Exception as e:
        print(e)

    # Create Access table
    try:
        c.execute('''
                  CREATE TABLE AccessTable(
                  FromEntityName VARCHAR(%d) NOT NULL,
                  ToType BOOLEAN NOT NULL,         /*True = Entity, False = Group */ 
                  ToName VARCHAR(%d) NOT NULL,      /*Group or Entity Name depending on ToType */ 
                  MaxAllowedTime float NOT NULL    /*Maximum allowable time for given relation*/   
                  )''' % (EntityNameMaxLen, EntityNameMaxLen))
    except Exception as e:
        print(e)

    # Create Session table
    try:
        c.execute('''
                  CREATE TABLE SessionTable(
                  FromEntityName VARCHAR(%d) NOT NULL,
                  ToEntityName VARCHAR(%d) NOT NULL,
                  AllowedUntil float NOT NULL,
                  SessionKey BINARY(%d) NOT NULL
                  )''' % (EntityNameMaxLen, EntityNameMaxLen, AESKEYSIZE))
    except Exception as e:
        print(e)

    # Save (commit) the changes
    conn.commit()

    conn.close()
    return


def addElement(EntityName: str, GroupName: str, PublicKey: int, DistKey: int, ValidUntil: float, ip: str, port: int):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (EntityName, GroupName, hex(PublicKey), hex(DistKey), ValidUntil, ip, port)
    try:
        c.execute('''
                  INSERT INTO EntityTable(
                  EntityName,
                  GroupName,
                  PublicKey,
                  DistKey,
                  ValidUntil,
                  ip,
                  port)
                  VALUES(?,?,?,?,?,?,?)
                  ''',
                  args)
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    return


def addSession(FromEntityName: str, ToEntityName: str, AllowedUntil: float, key: int):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (FromEntityName, ToEntityName, AllowedUntil, hex(key))
    removeSession(FromEntityName=FromEntityName, ToEntityName=ToEntityName)

    try:
        c.execute('''
                  INSERT INTO SessionTable(
                  FromEntityName,
                  ToEntityName,
                  AllowedUntil,
                  SessionKey)
                  VALUES(?,?,?,?)
                  ''', args)
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    return


def removeSession(FromEntityName: str, ToEntityName: str):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (FromEntityName, ToEntityName)

    try:
        c.execute('''
                  DELETE FROM SessionTable
                  WHERE FromEntityName=? AND ToEntityName=?
                  ''', args)
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    return
    

def removeElement(EntityName: str):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (EntityName, )

    try:
        c.execute('''
                  DELETE FROM EntityTable
                  WHERE EntityName=?
                  ''', args)
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    return


def getSessionKey(FromEntityName: str, ToEntityName: str):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (FromEntityName, ToEntityName)
    ret = None
    try:
        c.execute('''
                  SELECT SessionKey FROM SessionTable
                  WHERE FromEntityName=? AND ToEntityName=?
                  ''', args)
        ret = c.fetchone()

    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    if ret:
        ret = int(ret[0], 16)
    return ret


def updateDistKey(EntityName: str, DistKey: int, ValidUntil: float):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (hex(DistKey), ValidUntil, EntityName)

    try:
        c.execute('''
                 UPDATE EntityTable
                 SET DistKey=?, ValidUntil=?
                 WHERE EntityName=?
                  ''', args)
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    return


def updateIPaddr(EntityName: str, ip: str, port: int):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (ip, port, EntityName)

    try:
        c.execute('''
                 UPDATE EntityTable
                 SET ip=?, port=?
                 WHERE EntityName=?
                  ''', args)
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    return


def getValidity(GroupName: str):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (GroupName,)

    ret = None
    try:
        c.execute('''
                  SELECT ValPeriod FROM GroupTable
                  WHERE GroupName=?
                  ''', args)
        ret = c.fetchone()
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    if ret:
        return ret[0]
    else:
        return ret


def getPubKey(EntityName: str):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (EntityName,)

    ret = None
    try:
        c.execute('''
                  SELECT PublicKey FROM EntityTable
                  WHERE EntityName=?
                  ''', args)
        ret = c.fetchone()
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    if ret:
        ret = int(ret[0], 16)
    return ret


def getDistKey(EntityName: str):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (EntityName,)

    ret = None
    try:
        c.execute('''
                  SELECT DistKey FROM EntityTable
                  WHERE EntityName=?
                  ''', args)
        ret = c.fetchone()
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    if ret:
        return int(ret[0], 16)
    else:
        return None


# Session Key Valid Until
def getSKValidUntil():
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()

    ret = None
    try:
        c.execute('''
                  SELECT * FROM SessionTable
                  ''')
        ret = c.fetchall()
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    return ret


# Dist Key Valid Until
def getDKValidUntil():
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()

    ret = None
    try:
        c.execute('''
                  SELECT EntityName,ValidUntil FROM EntityTable
                  ''')
        ret = c.fetchall()
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    return ret

# Returns True if entity is in EntityTable, False otherwise
def isEntityReg(EntityName: str):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()

    args = (EntityName,)
    ret = None
    try:
        c.execute('''
                  SELECT EntityName FROM EntityTable
                  WHERE EntityName=?
                  ''', args)
        ret = c.fetchone()
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    if ret:
        return True
    else:
        return False


# Returns True if entity is in EntityTable, False otherwise
def getIPaddr(EntityName: str):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()

    args = (EntityName,)
    ret = None
    try:
        c.execute('''
                  SELECT ip,port FROM EntityTable
                  WHERE EntityName=?
                  ''', args)
        ret = c.fetchone()
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    return ret


def getAccess(FromEntityName: str, ToEntityName:str, reqTime: float=0):
    conn = sqlite3.connect(DatabaseFile)
    c = conn.cursor()
    args = (FromEntityName, ToEntityName, ToEntityName)
    ret = None
    try:
        c.execute('''
                  SELECT MaxAllowedTime FROM AccessTable
                  WHERE FromEntityName=? AND
                  ((ToType=1 AND ToName=?) OR 
                   (ToType=0 AND ToName IN 
                     (SELECT GroupName FROM EntityTable WHERE EntityName=?)
                    )
                   )
                  ''', args)
        ret = c.fetchone()
    except Exception as e:
        print("Error '%s' From file '%s'" % (e, __file__))

    conn.commit()
    conn.close()
    if ret and isEntityReg(ToEntityName):
        grantedTime = ret[0]
        if grantedTime>reqTime:
            grantedTime = reqTime
        return grantedTime
    else:
return None
