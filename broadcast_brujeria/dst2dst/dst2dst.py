import threading
from socket import *
import sys
import argparse
import random
import binascii

interface = "eth0" # Change to your interface

parser = argparse.ArgumentParser(description='dst2dst')
parser.add_argument('-m', dest='inMac', help='This is the source mac you will use')

# Transmit
t = socket(AF_PACKET, SOCK_RAW)
t.bind((interface, 0))
# Receive
r = socket( AF_PACKET, SOCK_RAW, ntohs(0x0003))
msgBufz = {} # These are buffers for tracking messages

def getChecksum(inData):
    b = inData[0]+inData[1]+inData[2]+inData[3]
    c = b % 256
    return c

def encodeMessage(inData):
    # What we are generating
    # ┌─eth.dst───────┐
    # 01 02 03 04 05 06
    # │  │  └─────────┴ XOR'd Data
    # │  └───────────── Checksum - Sum of the data bytes, which is XOR'd with the Key
    # └──────────────── XOR Key
    msgSeed = random.randrange(0,256)
    msgSeed = msgSeed | 1 # Ensure the bottom bit is always set
    msgBuf  = b""
    csum = getChecksum(inData)
    msgBuf += bytes([msgSeed])        # eth.dst[0]
    msgBuf += bytes([msgSeed ^ csum]) # eth.dst[1]
    msgBuf += bytes([( ( msgBuf[1] + csum ) % 256 ) ^ inData[0]]) # eth.dst[2]
    msgBuf += bytes([( ( msgBuf[2] + csum ) % 256 ) ^ inData[1]]) # eth.dst[3]
    msgBuf += bytes([( ( msgBuf[3] + csum ) % 256 ) ^ inData[2]]) # eth.dst[4]
    msgBuf += bytes([( ( msgBuf[4] + csum ) % 256 ) ^ inData[3]]) # eth.dst[5]
    return msgBuf

def decodeMessage(inData,esrc):
    # What we are decoding
    # ┌─eth.dst───────┐
    # 01 02 03 04 05 06
    # │  │  └─────────┴ XOR'd Data
    # │  └───────────── Checksum - Sum of the data bytes, which is XOR'd with the Key
    # └──────────────── XOR Key
    csum = inData[0] ^ inData[1]
    msgBuf = b""
    msgBuf += bytes([( ( inData[1] + csum ) % 256 ) ^ inData[2]])
    msgBuf += bytes([( ( inData[2] + csum ) % 256 ) ^ inData[3]])
    msgBuf += bytes([( ( inData[3] + csum ) % 256 ) ^ inData[4]])
    msgBuf += bytes([( ( inData[4] + csum ) % 256 ) ^ inData[5]])
    calcSum = getChecksum(msgBuf)
    # If the checksums match, we should print!
    if csum == calcSum:
        if esrc not in msgBufz.keys():
            msgBufz[esrc] = msgBuf
        else:
            msgBufz[esrc] += msgBuf
        if b"\x00" in msgBuf:
            print("{} -- {}".format(esrc, msgBufz[esrc].decode()))
            msgBufz[esrc] = b""

def rcv_message(inSock):
    while True:
        # What we need for our message
        packet = r.recvfrom(65565)
        packet = packet[0]
        ethdst  = packet[0:6]
        ethsrc  = packet[6:12].hex(':')
        ethtype = packet[12:14] # We want to check if this is our type
        if ethsrc == inMac:
            continue
        if ethtype == b"\x08\x06":
            decodeMessage(ethdst,ethsrc) # Attempt to decode

def genMessage(inData,inSock,srcMac):
    # //- Ethernet Header
    pkt =  b""
    pkt += encodeMessage(inData)
    pkt += srcMac
    pkt += b"\x08\x06"                 # eth.type (ARP)
    # //- ARP Message
    pkt += b"\x00\x01"                 # arp.hw.type        -- Hardware Type: Ethernet
    pkt += b"\x08\x00"                 # arp.proto.type     -- Protocol Type: IPv4
    pkt += b"\x06"                     # arp.hw.size        -- Hardware Size: 6
    pkt += b"\x04"                     # arp.proto.size     -- Protocol Size: 4
    pkt += b"\x00\x01"                 # arp.opcode         -- Opcode: Request
    pkt += b"\x00\x11\x22\x33\x44\x55" # arp.src.hw_mac     -- Source MAC Address
    pkt += b"\x0a\x00\x01\x0a"         # arp.src.proto_ipv4 -- Source IP: 10.0.1.10
    pkt += b"\x00\x00\x00\x00\x00\x00" # arp.dst.hw_mac     -- Target MAC Address
    pkt += b"\x0a\x00\x01\x0b"         # arp.dst.proto_ipv4 -- Target IP: 10.0.1.11
    
    inSock.send(pkt)

def send_message(inSock,srcMacS):
    srcMac = binascii.unhexlify(srcMacS.replace(':',''))
    for line in sys.stdin:
        msg = line.rstrip()
        msg = msg.encode('latin-1')
        padding = (len(msg) % 4) # Using this to calculate how many padding bytes are needed
        if padding != 0:
            msg += b"\x00"*(4-padding) # Adds padding bytes if needed
        else:
            msg += b"\x00\x00\x00\x00" # This adds one null message at the end to signify the message is done
        mlen = len(msg)
        i = 0
        while i < mlen:
            chunk = msg[i:i+4]
            genMessage(chunk,t,srcMac)
            i = i+4
        print("{} -- {}".format(srcMacS, msg.decode()))

if __name__ == "__main__":
    args   = parser.parse_args()
    inMac  = args.inMac

    x = threading.Thread(target=rcv_message, args=(r,))
    x.start()
    y = threading.Thread(target=send_message, args=(t,inMac))
    y.start()
