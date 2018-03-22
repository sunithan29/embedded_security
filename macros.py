# flags [8bit] definitions macro
ENCPTD = 0
REQREG = 1  # registration request sent, used by entities
ACPTREG = 2  # registration request accepted, used by auth servers
RJCTREG = 3  # registration request rejected, used by auth servers
ACKAUTH = 4  # acknowledge to auth server
REQACC = 5  # request to access entity and session key gen, used by entities
ACPTACC = 6  # access request accepted, used by auth servers
RJCTACC = 7  # access request rejected, used by auth servers
REQCOMM = 8  # communication request to entity by entity
RESPCOMM = 9  # Communication response from entity to entity
ACKACC = 10
NONCE = 11

CNFACC = 12

EntityNameMaxLen = 50
GroupNameMaxLen = 20
sep = ':'  # separator
sep = sep.encode()

AESKEYSIZE = 128
RSAKEYSIZE = 2048
