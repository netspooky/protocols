from socket import *
import sys

# ZEROETH.PY - Simple null frame transport over ethernet
# Run:
# $ cat file | sudo python3 zeroeth.py
# On the remote computer:
# $ sudo python3 zeroeth.client.py

interface = "eth0" # Your network interface
message = sys.stdin.buffer.read()

def getHeader():
    # Some routers, OSes, and other things a packet may pass through have issues with small 
    # frames that don't have a designated ethernet type. This header basically ensures that
    # at least 64 bytes is sent per frame.
    #
    # Minimal Ethernet Frame Layout
    #
    #         ┌dst──────────────┬src──────────────┬type─┐
    #   0000: └01─00─00─00─00─00┴00─00─00─00─00─00┴00─00┘00 00
    #   0010:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    #   0020:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    #   0030:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    # 
    # As long as the lowest bit of the eth.dst field is set to 1, the packet is multicast.

    data =  b"\xFF\xFF\xFF\xFF\xFF\xFF" # eth.dst multicast
    data += b"\x5a\x45\x5a\x45\x5a\x45"
    data += b"\x5a\x45" # eth.type
    data += b"\x00" * 50 # The rest is just padding.
    return data

def sendData(inData,inSock):
    framee =  getHeader()
    framee += b"\x00" * inData # Creates a frame with null bytes that add up to the bytes value
    inSock.send(framee)

s = socket(AF_PACKET, SOCK_RAW)
s.bind((interface, 0))

for i in message:
    sendData(i,s)
