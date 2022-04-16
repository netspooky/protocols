from socket import *
import time
import sys
# ZEROETH_ROUTING_MIN.CLIENT.PY
interface = "ens33" # Change to your interface
nodeaddr = 0 # Range is 0 through 3
srvaddr = 1 # This is who we are sending data to
timeOut = 3 # Need this so we can ensure all the data comes back from the server

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

def decodeMessage(inSock):
  decodeTimeout = time.time() + timeOut # Time limit for listener
  outbuf = ""
  
  while time.time() < decodeTimeout:
      try:
          packet  = inSock.recvfrom(65565) # The buffer
          packet  = packet[0]     # Our packet
          byte0   = packet[0] # The very first byte 
          ethtype = packet[12:14] # The ethernet type
  
          if ethtype == b"\x00\x00": # Match the ethernet type
              # Check the first byte now to see if it's multicast
              if byte0 & 1:
                  #if byte0 & 0x80:
                  #    bindata = 1 # Check the mode - Not implemented yet
                  dst = byte0 & 0x30 # This preserves bits 5 and 6
                  dst = dst >> 4     # Turn this into a value
                  src = byte0 & 0x0C # This preserves bits 3 and 4
                  src = src >> 2     # Turn this into a value
                  if dst == nodeaddr: # This message is for us
                    decodedpkt = len(packet) - 0x40
                    outbuf += chr(decodedpkt)
                  if byte0 & 0x40:
                      print(outbuf)
                      outbuf = ""
      except Exception as e:
        print()

# Receive
r = socket( AF_PACKET, SOCK_RAW, ntohs(0x0003))
r.settimeout(timeOut)
# Transmit
t = socket(AF_PACKET, SOCK_RAW)
t.bind((interface, 0))

while True:
    for line in sys.stdin:
        if 'exit' == line.rstrip():
            break
        encodeMessage(line.encode('latin-1'),t,srvaddr) # Sending data
        decodeMessage(r)
