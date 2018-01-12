import time
import struct
import socket
import sys
import select
import signal


from Crypto.Util.number import getRandomNumber
from Crypto.Cipher import AES
import database
from logger import logger as log

from macros import *
from inspect import currentframe

# importing rsa keys
import rsa_keys

req_list = {}  # saves requested list data, EntityName: pubkey, nonce

LOGGING = False
DEBUG = True
authName = "auth1"
authNameLength = len(authName)
certificate = "Certificate file"  # give RSA certificate file here as text
certificateLength = len(certificate)

AUTHPORT = 5555
TIMER = 5
BUFFER = 1024
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def getHash(data: bytes, key: bytes, iv: bytes):
    data_len = len(data) // 8
    cbc_hash = AES.new(key, AES.MODE_CBC, iv)
    data = cbc_hash.encrypt(data)
    data_int = int.from_bytes(data, 'big')
    hash_value = data_int & 0xffffffffffffffff
    for i in range(0, data_len-1):
        data_int = data_int >> 64
        hash_value = hash_value ^ (data_int & 0xffffffffffffffff)
    return hash_value.to_bytes(8, 'big')


def process_padding(data: bytes = ''):
    # making string 32 bit aligned
    data_length = len(data)
    data_rest = data_length % 16
    if data_rest != 0:
        data = data.ljust(data_length + 16 - data_rest, b'\0')
    return data


def str2ip(ip_str: str):
    ip = ip_str.split('.')
    if not len(ip) == 4:
        raise ValueError("IP address is not in proper format(ie x.x.x.x")
    for byte in ip:
        if int(byte) not in range(0, 256):
            raise ValueError("IP address values are not proper (ie between 0.0.0.0 and 255.255.255.255)")
    return struct.pack('4B',int(ip[0]),int(ip[1]),int(ip[2]),int(ip[3]))


def ip2str(ip: bytes):
    if len(ip) > 4:
        raise ValueError("IP address is not in proper (ie 32-bit in Length")
    ip_str = str(ip[0]) +'.'+ str(ip[1]) +'.'+str(ip[2]) +'.'+str(ip[3])
    return ip_str


def rsa_encrypt(key: int, resp: bytes):
    #rsa encryption should be done here
    resp_length = len(resp)
    data_length = resp_length // 127
    if resp_length % 127:
        data_length = data_length + 1
        for i in range(0, (127-resp_length%127)):
            resp = resp + b'\0'

    data = b''
    for i in range(0, data_length):
        x = int.from_bytes(b'\0'+resp[i*127:(i*127)+127], 'big')
        x = pow(x, rsa_keys.public_expo, key)
        data = data + x.to_bytes(128, 'big')

    return data


def rsa_decrypt(resp: bytes):
    # write decrypt code here
    resp_length = len(resp)
    if (resp_length % 128) != 0:
        print("Invalid cypher size")
        return None
    data_length = resp_length // 128

    data = b''
    for i in range(0, data_length):
        x = int.from_bytes(resp[(i*128): (i*128) + 128], 'big')
        x = pow(x, rsa_keys.private_expo, rsa_keys.modulus)
        x = x.to_bytes(128, 'big')
        data = data + x[1:128]

    return data

def rsa_verify(key: int, cert: int):
    if key >= 1<<1024:
        return False
    if cert >= 1<<1024:
        return False

    genkey = pow(cert, rsa_keys.public_expo, rsa_keys.root_modulus)

    if genkey == key:
        return True

    return False




def aes_encrypt(EntityName: str, data: bytes):
    key = database.getDistKey(EntityName)
    iv = getRandomNumber(128)
    if DEBUG:
        print("Encrypting data for " + EntityName)
        print("Using AES key: %s\nand iv : %s" % (hex(key), hex(iv)))
    # do aes encryption here
    iv = iv.to_bytes(16, 'big')
    key = key.to_bytes(16, 'big')
    cbc = AES.new(key, AES.MODE_CBC, iv)
    data = process_padding(data)
    data = cbc.encrypt(data)
    hash_code = getHash(data=data, key=key, iv=iv)
    return iv + hash_code + data


def aes_decrypt(EntityName: str, data: bytes, ip_addr: tuple):
    key = database.getDistKey(EntityName)
    if key:
        if DEBUG:
            print("Decrypting data from " + EntityName)
            print("Using AES key: %s" % hex(key))
        # write aes decrypt algorythem here
        key = key.to_bytes(16, 'big')
        data = data[1:]  # ENCPD
        iv = data[0:16]
        hash_value1 = data[16:24]
        data = process_padding(data[24:])
        hash_value2 = getHash(data=data, key=key, iv=iv)
        if hash_value1 == hash_value2:
            cbc = AES.new(key, AES.MODE_CBC, iv)
            data = cbc.decrypt(data)
            flag = data[0]
            function_pointer[flag](EntityName=EntityName, data=data, ip_addr=ip_addr)
        else:
            print("Data from %s got corrupted" % EntityName)
            if DEBUG:
                print(hex(int.from_bytes(hash_value1, 'big')))
                print(hex(int.from_bytes(hash_value2, 'big')))
                print(hex(int.from_bytes(iv, 'big')))
                cbc = AES.new(key, AES.MODE_CBC, iv)
                data = cbc.decrypt(data)
                print(data)
    return

# nonce handler
def nonceHandler(EntityName: str, data: bytearray, ip_addr: tuple):
    data = data[1:]
    data = rsa_decrypt(data[0:128])
    if not data:
        return
    nonceGen = data[0:16]
    nonceGot = data[16:32]
    print("Verifing Nonce got back from %s" % EntityName)
    if DEBUG:
        print("Got nonce1: %s" % hex(int.from_bytes(nonceGen, 'big')))
        print("Got nonce2: %s" % hex(int.from_bytes(nonceGot, 'big')))
    valid = False
    nonceGen = int.from_bytes(nonceGen, 'big')
    if nonceGen == req_list[EntityName]['nonce']:
        print("Nonce verified for %s as **valid**" % EntityName)
        valid = True
    else:
        print("Nonce verified for %s as **invalid**" % EntityName)
        print("Sent nonce: %s" % hex(req_list[EntityName]['nonce']))
        req_list.pop(EntityName)
    if valid:
        if not database.isEntityReg(EntityName):
            ip, port = ip_addr
            groupName = req_list[EntityName]['groupname']
            validUntil = time.time() + (3600 * database.getValidity(groupName))
            print("Generating Distribution Key")
            distKey = getRandomNumber(AESKEYSIZE)
            pubkey = req_list[EntityName]['pubkey']
            print("Adding %s to EntityTable" % EntityName)
            database.addElement(EntityName=EntityName,
                                GroupName=groupName,
                                PublicKey=pubkey,
                                DistKey=distKey,
                                ValidUntil=validUntil,
                                ip=ip,
                                port=port)
            req_list.pop(EntityName)
        else:
            print("%s is already registered" % EntityName)
            distKey = database.getDistKey(EntityName)
            pubkey = database.getPubKey(EntityName)
        print("Distkey: %s" % hex(distKey))
        # send registration ack
        distKey = distKey.to_bytes(16, 'big')
        resp = rsa_encrypt(key=pubkey, resp=nonceGot+distKey)
        msg = struct.pack("!%dscB128s128s128s" % authNameLength,
                          authName.encode(), sep, ACPTREG,
                          rsa_keys.modulus.to_bytes(128, 'big'),
                          rsa_keys.cert.to_bytes(128, 'big'),
                          resp)
        print("Sending nonce back and distkey to %s" % EntityName)
        serverSocket.sendto(msg, ip_addr)
        print()
        return
    else:
        print("Sending reject message to %s" % EntityName)
        reject = rsa_encrypt(req_list[EntityName]['pubkey'], RJCTREG.to_bytes(1,'big'))
        resp = struct.pack("!%dscB128s128s128s" % authNameLength,
                           authName.encode(), sep, RJCTREG,
                           rsa_keys.modulus.to_bytes(128, 'big'),
                           rsa_keys.cert.to_bytes(128, 'big'),
                           reject
                           )
        serverSocket.sendto(resp, ip_addr)
        req_list.pop(EntityName)
        print()
        return
# registration request handler
def reqregHandler(EntityName: str, data: bytearray, ip_addr: tuple):
    groupNameLength = data[1]
    groupName = data[2:2+groupNameLength].decode()
    publicKey_starts = 2 + groupNameLength
    publicKey = data[publicKey_starts: publicKey_starts+128]
    publicKey = int.from_bytes(publicKey, 'big')
    entityCert_starts = publicKey_starts+128
    entityCert = data[entityCert_starts: entityCert_starts + 128]
    entityCert = int.from_bytes(entityCert, 'big')

    if DEBUG:
        print("Processing Registration request for %s" % EntityName)
        print("Group Name:", groupName)
        print("IP: %s Port: %d" % ip_addr)
        print("Present public module by " + EntityName)
        temp = hex(publicKey).split('x')[1].zfill(128)
        for i in range(0,4):
            print("\t%s" % temp[32*i:(32*i)+32])
        print("Presented certificate by " + EntityName)
        temp = hex(entityCert).split('x')[1].zfill(128)
        for i in range(0,4):
            print("\t%s" % temp[32*i:(32*i)+32])

    print("Validating certificate given by " + EntityName)
    valid = False
    # Validating certificate here
    if rsa_verify(key=publicKey, cert=entityCert):
        print("Certificate verified as **valid**")
        valid = True
    else:
        print("Certificate verified as **invalid**")
        print("Admin shall be informed")

    isGroup = database.getValidity(groupName)
    if not isGroup:
        valid = False
        print("GroupName is not in group table")

    if valid:
        if DEBUG:
            print("Generating 128bit Nonce")
        nonceGen = getRandomNumber(AESKEYSIZE)
        print("nonce = %s" % hex(nonceGen))
        new_req = {}
        new_req.update({'nonce': nonceGen})
        new_req.update({'pubkey': publicKey})
        new_req.update({'groupname': groupName})
        req_list.update({EntityName: new_req})
        nonceGen = nonceGen.to_bytes(16, 'big')
        nonceGen = rsa_encrypt(publicKey, nonceGen)
        resp = struct.pack("!%dscB128s128s128s" % authNameLength,
                           authName.encode(), sep, NONCE,
                           rsa_keys.modulus.to_bytes(128, 'big'),
                           rsa_keys.cert.to_bytes(128, 'big'),
                           nonceGen
                           )
        serverSocket.sendto(resp, ip_addr)
        if DEBUG:
            print("Nonce with credentials are send to %s" % EntityName)

    else:
        print("Sending reject message to %s" % EntityName)
        reject = rsa_encrypt(publicKey, int.to_bytes(RJCTREG,1,'big'))
        resp = struct.pack("!%dscB128s128s128s" % authNameLength,
                           authName.encode(), sep, RJCTREG,
                           rsa_keys.modulus.to_bytes(128, 'big'),
                           rsa_keys.cert.to_bytes(128, 'big'),
                           reject
                           )
        serverSocket.sendto(resp, ip_addr)
    print()
    return


def reqAccessHandler(EntityName: str, data: bytes, ip_addr: tuple):
    Entity2length = data[1]
    Entity2Name = data[2:2+Entity2length].decode()
    reqTime = struct.unpack("!I", bytes(data[2+Entity2length:2+Entity2length+4]))[0]

    print("Processing Access request from %s to %s for %dm" % (EntityName, Entity2Name, reqTime))
    grantedTime = database.getAccess(FromEntityName=EntityName,
                                     ToEntityName=Entity2Name,
                                     reqTime=reqTime)
    if grantedTime:
        print("%s is granted access to %s for %sm time" % (EntityName, Entity2Name, grantedTime))
        allowedUntil = time.time() + (60*grantedTime)

        sessionKey = database.getSessionKey(FromEntityName=Entity2Name,
                                            ToEntityName=EntityName)
        if not sessionKey:
            sessionKey = getRandomNumber(AESKEYSIZE)

        database.addSession(FromEntityName=EntityName,
                            ToEntityName=Entity2Name,
                            AllowedUntil=allowedUntil,
                            key=sessionKey)


        if DEBUG:
            print("Generated Session key: %s" % hex(sessionKey))

        sessionKey1 = ((sessionKey >> 64) & ((1 << 64)-1))
        sessionKey2 = (sessionKey & ((1 << 64)-1))

        ip, port = database.getIPaddr(EntityName)
        ip2, port2 = database.getIPaddr(Entity2Name)
        if not ip2 or not port2 or not ip or not port:
            print("Some problem with database")
            exit(10)

        print("Sendnig session key to %s" % EntityName)
        data = struct.pack(("!BB%dsI4sHQQ" % Entity2length),
                           ACPTACC, Entity2length,
                           Entity2Name.encode(), int(grantedTime),
                           str2ip(ip2), port2,
                           sessionKey1, sessionKey2)
        msg = aes_encrypt(EntityName=EntityName, data=data)
        msg = struct.pack(("!%dscB" % authNameLength), authName.encode(), sep, ENCPTD) + msg
        serverSocket.sendto(msg, (ip, port))

        print("Sendnig acknowledgement with session key to %s" % Entity2Name)
        EntityNameLength = len(EntityName)
        data = struct.pack(("!BB%dsI4sHQQ" % EntityNameLength),
                           ACKACC, EntityNameLength,
                           EntityName.encode(), int(grantedTime),
                           str2ip(ip), port,
                           sessionKey1, sessionKey2)
        msg = aes_encrypt(EntityName=Entity2Name, data=data)
        msg = struct.pack(("!%dscB" % authNameLength), authName.encode(), sep, ENCPTD) + msg
        serverSocket.sendto(msg, (ip2, port2))

    else:
        print("%s is rejected to access to %s" % (EntityName, Entity2Name))
        print("Sending reject message to %s" % EntityName)
        data = struct.pack(("!BB%ds" % Entity2length),
                           RJCTACC, Entity2length,
                           Entity2Name.encode())
        msg = aes_encrypt(EntityName=EntityName, data=data)
        msg = struct.pack(("!%dscB" % authNameLength), authName.encode(), sep, ENCPTD) + msg
        serverSocket.sendto(msg, ip_addr)

    print()
    return


def ackAuthHandler(EntityName: str, data: bytearray, ip_addr: tuple):
    # Nothing to do here
    return

last_time = time.time()
def timerHandler():
    global last_time
    #print("!!!Time-out!!!")
    current_time = time.time()
    for entry in database.getSKValidUntil():
        if current_time >= entry[2]:
            print("Session timed-out for %s to %s" % (entry[0], entry[1]))
            database.removeSession(entry[0], entry[1])

    if (current_time - last_time) > (60 * TIMER):
        last_time = current_time
        for entry in database.getDKValidUntil():
            if current_time >= entry[1]:
                print("DistKey timed-out for %s" % (entry[0]))
                database.removeElement(entry[0])
                
    return


def main():
    database.createTables()
    serverSocket.bind(('', AUTHPORT))

    fd = sys.stdin.fileno()
    #signal.signal(signal.SIGALRM, timerHandler)
    #signal.alarm(5)
    print()
    while True:
        try:
            readable, writable, excep = select.select([serverSocket, fd], [], [], TIMER)
        except KeyboardInterrupt:
            print("Terminating Auth Server...")
            serverSocket.close()
            sys.exit(0)
        except:
            print("Unknown Exception occurred:")
            continue
        else:
            if fd in readable:
                inputLine = input()
                inputLine = str(inputLine).split(' ')

            if serverSocket in readable:
                data, addr = serverSocket.recvfrom(BUFFER)
                splitedData = data.split(sep)
                EntityName = splitedData[0].decode()
                EntityNameLength = len(EntityName)
                data = data[EntityNameLength+1:]
                flag = data[0]
                function_pointer[flag](EntityName=EntityName, data=data, ip_addr=addr)

        timerHandler()
    # Loop, printing any data we receive

# List of various function handler
function_pointer = {ENCPTD: aes_decrypt,
                    REQREG: reqregHandler,
                    REQACC: reqAccessHandler,
                    ACKAUTH: ackAuthHandler,
                    NONCE : nonceHandler}
if __name__ == '__main__':

    main()

'''
packet formats = entity name:status[8bit]:data[variable] CoSV(Colon-Separated Values) format
[plaintext]    # entity name : REQREG[8bit] : type[8bit] : group name : length of cert in bytes[32bit] : Certificate
[RSA]          # auth name   : RJCTREG[8bit] : length of cert in bytes[32bit] : Certificate
[RSA]          # auth name   : ACPTREG[8bit] : length of cert in bytes[32bit] : Certificate : dist key
[AES-GCM]      # entity name : REQACC[8bit]  : length of entity name : entity name : access time in minutes (requested)
[AES-GCM]      # auth name   : RJCTACC[8bit] : length of entity name : entity name
[AES-GCM]      # auth name   : ACPTACC[8bit]  : length of entity name : entity name : access time in minutes (granted) : session key
[AES-GCM]      # entity name : REQCOMM[8bit] : data to n fro application
[AES-GCM]      # entity name : RESPCOMM[8bit]: data to n fro application

all encrypted message formats
            # entity/auth name : ENCPTD[8bit] : Encrypted message in above format without entity/auth name
'''
