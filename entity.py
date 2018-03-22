import time
import struct
from socket import *
import sys
import select
import signal
from Crypto.Util.number import getRandomNumber
from Crypto.Cipher import AES

# import macros
from macros import *

# importing rsa keys
import rsa_keys
'''''''''''''''''''''logging'''''''''''''''''''''''''''''
import logging
logger = logging.getLogger('myapp')
hdlr = logging.FileHandler(__file__+'.'+sys.argv[1]+'.log')
formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)
''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
to_access_table = {}
from_access_table = {}

DEBUG = True
entityName = sys.argv[1]
entityNameLength = len(entityName)
groupName = "Public"
groupNameLength = len(groupName)
my_ip = sys.argv[2]
my_port = int(sys.argv[3])
nonceGen = 0

cetrificate = "Certificate file"  # give RSA certificate file here as text
cetrificateLength = len(cetrificate)

AUTH = ''
authIP = ("192.168.0.104", 5555)
BUFSIZE = 1024

s = socket(AF_INET, SOCK_DGRAM)


def getHash(data: bytes, key: int, iv: int):
    data_len = len(data) // 8
    cbc_hash = AES.new(key, AES.MODE_CBC, iv)
    data = cbc_hash.encrypt(data)
    data_int = int.from_bytes(data, 'big')
    hash_value = data_int & 0xffffffffffffffff
    for i in range(0, data_len-1):
        data_int = data_int >> 64
        hash_value = hash_value ^ (data_int & 0xffffffffffffffff)
    return hash_value.to_bytes(8, 'big')


def process_padding(data: str = ''):
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
    ip_str = str(ip[0]) + '.' + str(ip[1]) + '.' + str(ip[2]) + '.' + str(ip[3])
    return ip_str


# class Entity:
def aes_decrypt(xEntityName: str, data: bytearray, ip_addr: tuple):
    key = None
    if xEntityName in to_access_table:
        key = to_access_table[xEntityName]["sessionKey"]
    elif xEntityName in from_access_table:
        key = from_access_table[xEntityName]["sessionKey"]
    if key:
        if DEBUG:
            print("Decrypting data from %s using AES key %s" % (xEntityName, hex(key)))
        # write aes decrypt algorithm here
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
            try:
                function_pointer[flag](xEntityName=xEntityName, data=data, ip_addr=ip_addr)
            except Exception as e:
                print("Error Occurred: %s" % e)

        else:
            print("Data from %s got corrupted" % xEntityName)
            if DEBUG:
                print(hash_value1)
                print(hash_value2)
                print(iv)
    return


def aes_encrypt(data: bytes, xEntityName: str):
    if xEntityName in to_access_table:
        key = to_access_table[xEntityName]["sessionKey"]
    elif xEntityName in from_access_table:
        key = from_access_table[xEntityName]["sessionKey"]
    iv = getRandomNumber(128)
    if DEBUG:
        print("Encrypting data for " + xEntityName)
        print("Using AES key: %s and iv : %s" % (hex(key), hex(iv)))
    # do aes encryption here
    iv = iv.to_bytes(16, 'big')
    key = key.to_bytes(16, 'big')
    cbc = AES.new(key, AES.MODE_CBC, iv)
    data = process_padding(data)
    data = cbc.encrypt(data)
    hash_code = getHash(data=data, key=key, iv=iv)
    return iv + hash_code + data


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



def reqRegistration():
    s.bind((my_ip, my_port))

    msg = struct.pack("!%dscBB%ds128s128s" %
                      (entityNameLength, groupNameLength),
                      entityName.encode(), sep, REQREG,
                      groupNameLength, groupName.encode(),
                      rsa_keys.modulus.to_bytes(128, 'big'), rsa_keys.cert.to_bytes(128, 'big'))
    s.sendto(msg, authIP)

    while True:
        data, fromaddr = s.recvfrom(BUFSIZE)
        if fromaddr == authIP:
            #print(data)
            splitedData = data.split(sep)
            authName = splitedData[0].decode()
            authNameLength = len(authName)
            authPubKey_starts = authNameLength+2
            authPubKey = data[authPubKey_starts:authPubKey_starts+128]
            authPubKey = int.from_bytes(authPubKey, 'big')
            authCert_starts = authPubKey_starts+128
            authCert = data[authCert_starts: authCert_starts + 128]
            authCert = int.from_bytes(authCert, 'big')

            if DEBUG:
                print("Pubkey and Certificate of %s" % authName)
                print(hex(authPubKey))
                print(hex(authCert))

            print("Validating certificate given by " + authName)
            # Validating certificate here
            if rsa_verify(key=authPubKey, cert=authCert):
                print("Certificate verified as **valid**")
                valid = True
            else:
                print("Certificate verified as **invalid**")
                print("Admin shall be informed")
                valid = False

            if valid:
                flag = data[authNameLength+1]
                if flag == RJCTREG:
                    print("Registration request rejected")
                    s.close()
                    return False

                if flag == NONCE:
                    nonce_starts = authCert_starts + 128
                    nonceGot = data[nonce_starts:nonce_starts+128]
                    nonceGot = rsa_decrypt(nonceGot)[0:16]
                    nonceGen = getRandomNumber(AESKEYSIZE).to_bytes(16, 'big')
                    resp = rsa_encrypt(key=authPubKey, resp=nonceGot + nonceGen)
                    msg = struct.pack("!%dscB128s" % entityNameLength,
                                      entityName.encode(), sep, NONCE,
                                      resp
                                      )
                    s.sendto(msg, authIP)

                if flag == ACPTREG:
                    print("Checking nonce for %s" % authName)
                    data_starts = authCert_starts + 128
                    data = data[data_starts:data_starts+128]
                    print(data)
                    data = rsa_decrypt(data)
                    print(data)
                    nonceGot = data[0:16]
                    if nonceGen == nonceGot:
                        print("Nonce verified as **valid**")
                    else:
                        print("Nonce verified as **invalid**")
                        print(nonceGot)
                        print(nonceGen)
                        s.close()
                        return False
                    distkey = int.from_bytes(data[16:32], 'big')
                    if DEBUG:
                        print("distkey:%s" % hex(distkey))
                    global AUTH
                    AUTH = authName
                    newEntry = {}
                    newEntry.update({"sessionKey": distkey})
                    newEntry.update({"ip_addr": fromaddr})
                    to_access_table.update({authName: newEntry})
                    from_access_table.update({authName: newEntry})
                    signal.alarm(2*3600)
                    return True


def reqAccess(xEntityName: str, acctime: int):
    if AUTH in to_access_table:
        xEntityNameLength = len(xEntityName)
        if DEBUG:
            print("Requesting Auth to access %s for %dm time." % (xEntityName, acctime))
        msg = struct.pack(("!BB%dsI" % xEntityNameLength),
                          REQACC, xEntityNameLength,
                          xEntityName.encode(), acctime)
        msg = aes_encrypt(data=msg, xEntityName=AUTH)
        data = struct.pack(("!%dscB" % entityNameLength), entityName.encode(), sep, ENCPTD) + msg
        s.sendto(data, authIP)
    return


def ackaccHandler(xEntityName: str, data: bytes, ip_addr: tuple):
    xEntity2Length = data[1]
    xEntity2Name = data[2:2 + xEntity2Length].decode()
    grantedTime = struct.unpack("!I", bytes(data[2 + xEntity2Length:2 + xEntity2Length + 4]))[0]

    ip = ip2str(bytes(data[2 + xEntity2Length + 4:2 + xEntity2Length + 4 + 4]))
    port = int.from_bytes(data[2 + xEntity2Length + 4 + 4:2 + xEntity2Length + 4 + 4 + 2], 'big')

    Skey = int.from_bytes(data[2 + xEntity2Length + 4 + 4 + 2:2 + xEntity2Length + 4 + 4 + 2 + 16], 'big')
    if DEBUG:
        print(hex(Skey))

    print("Got acknowledgement to access from %s for %dm" % (xEntity2Name, grantedTime))
    grantedTime = time.time() + (grantedTime * 60)
    newEntry = {}
    newEntry.update({"sessionKey": Skey})
    newEntry.update({"time": grantedTime})
    newEntry.update({"ip_addr": (ip, port)})
    from_access_table.update({xEntity2Name: newEntry})

    data = struct.pack("!B", ACKAUTH)
    data = aes_encrypt(data, xEntityName)
    data = struct.pack(("!%dscB" % entityNameLength), entityName.encode(), sep, ENCPTD) + data
    s.sendto(data, ip_addr)
    return


def sendMsg(xEntityName: str, msg: str):
    current_time = time.time()
    if xEntityName in to_access_table:
        if current_time > to_access_table[xEntityName]["time"]:
            to_access_table.pop(xEntityName)
            print("Timed out session with %s" % xEntityName)
        else:
            ip_addr = to_access_table[xEntityName]['ip_addr']
            msgLength = len(msg)
            msg = struct.pack(("!B%ds" % msgLength), REQCOMM, msg.encode())
            msg = aes_encrypt(msg, xEntityName)
            data = struct.pack(("!%dscB" % entityNameLength), entityName.encode(), sep, ENCPTD) + msg
            s.sendto(data, ip_addr)
    else:
        print("%s is not in acceess list" % xEntityName)
    return


def acptaccHandler(xEntityName: str, data: bytes, ip_addr: tuple):
    xEntity2Length = data[1]
    print(xEntity2Length)

    xEntity2Name = data[2:2+xEntity2Length].decode()
    grantedTime = int.from_bytes(data[2+xEntity2Length:2+xEntity2Length+4], 'big')
    ip = ip2str(bytes(data[2+xEntity2Length+4:2+xEntity2Length+4+4]))
    port = struct.unpack('!H', bytes(data[2+xEntity2Length+4+4:2+xEntity2Length+4+4+2]))[0]

    Skey = int.from_bytes(data[2+xEntity2Length+4+4+2:2+xEntity2Length+4+4+2+16], 'big')
    if DEBUG:
        print(hex(Skey))

    print("Access granted for %s for %dm" % (xEntity2Name, grantedTime))
    grantedTime = time.time() + (grantedTime * 60)
    newEntry = {}
    newEntry.update({"sessionKey": Skey})
    newEntry.update({"time": grantedTime})
    newEntry.update({"ip_addr": (ip, port)})
    to_access_table.update({xEntity2Name: newEntry})
    return


def rjctaccHandler(xEntityName: str, data: bytearray, ip_addr: tuple):
    # Nothing to do here
    xEntity2Length = data[1]
    print(hex(data[1]))
    xEntity2Name = data[2:2 + xEntity2Length].decode()
    print("Access denied for %s by %s" % (xEntity2Name, xEntityName))
    return


def respcommHandler(xEntityName: str, data: bytearray, ip_addr: tuple):
    # this is example of echo client/server
    current_time = time.time()
    if xEntityName in to_access_table:
        if current_time > to_access_table[xEntityName]["time"]:
            to_access_table.pop(xEntityName)
        else:
            if DEBUG:
                print("Got response from %s" % xEntityName)

            print(data[1:])
    return


def reqcommHandler(xEntityName: str, data: bytearray, ip_addr: tuple):
    # this is example of echo client/server
    current_time = time.time()
    if DEBUG:
        print("Processing Comm Request from %s" % xEntityName)
    if xEntityName in from_access_table:
        if current_time > (from_access_table[xEntityName]["time"]):
            from_access_table.pop(xEntityName)
            print("Timed out session with %s" % xEntityName)
        else:
            msg = data[1:].decode()
            print("Got message: " + msg)
            ip_addr = from_access_table[xEntityName]['ip_addr']
            msgLength = len(msg)
            msg = struct.pack(("!B%ds" % msgLength), RESPCOMM, msg.encode())
            msg = aes_encrypt(msg, xEntityName)
            data = struct.pack(("!%dscB" % entityNameLength), entityName.encode(), sep, ENCPTD) + msg
            s.sendto(data, ip_addr)
    else:
        print("%s is not in acceess list" % xEntityName)
    return


def timerHandler(x,y):
    if not reqRegistration():
        exit()


def main():
    if reqRegistration():
        fd = sys.stdin.fileno()
        signal.signal(signal.SIGALRM, timerHandler)
        signal.alarm(5)
        while True:
            try:
                readable, writable, excep = select.select([s, fd], [], [])
            except KeyboardInterrupt:
                print("Terminating Entity...")
                s.close()
                sys.exit(0)
            except Exception as e:
                print("Unknown Exception occurred:%s" % e)
                continue
            else:
                if fd in readable:
                    inputLine = input()
                    inputLine = str(inputLine).split(' ')
                    inputLineLength = len(inputLine)
                    if 'access' == inputLine[0]:
                        if inputLineLength == 3:
                            xEntityName = inputLine[1]
                            acctime = int(inputLine[2])
                            reqAccess(xEntityName=xEntityName, acctime=acctime)
                        else:
                            print("Insufficient arguments")

                    elif 'send' == inputLine[0]:
                        if inputLineLength == 3:
                            xEntityName = inputLine[1]
                            msg = inputLine[2]
                            sendMsg(xEntityName=xEntityName, msg=msg)
                        else:
                            print("Insufficient arguments")

                    elif 'to' == inputLine[0]:
                        if inputLineLength == 1:
                            for each in to_access_table:
                                print(str(each) + '=' + str(to_access_table[each]))

                    elif 'from' == inputLine[0]:
                        if inputLineLength == 1:
                            for each in from_access_table:
                                print(str(each) + '=' + str(from_access_table[each]))

                if s in readable:
                    data, addr = s.recvfrom(BUFSIZE)
                    splitedData = data.split(sep)
                    xEntityName = splitedData[0].decode()
                    xEntityNameLength = len(xEntityName)
                    data = data[xEntityNameLength + 1:]
                    flag = data[0]
                    function_pointer[flag](xEntityName=xEntityName, data=data, ip_addr=addr)
    else:
        exit(0)

function_pointer = {ENCPTD: aes_decrypt,
                    ACPTACC: acptaccHandler,
                    ACKACC: ackaccHandler,
                    RJCTACC: rjctaccHandler,
                    RESPCOMM: respcommHandler,
                    REQCOMM: reqcommHandler}

if __name__ == '__main__':
main()
