import base64
import sys
import random
from socket import *
import argparse
import threading

parser = argparse.ArgumentParser(description='srcdirect')
parser.add_argument('-i', dest='interface', help='Your interface')
parser.add_argument('-s', dest='srcnode', type=int, help='Your node number, range (1-15)')

args   = parser.parse_args()
interface = args.interface
srcnode = args.srcnode
if srcnode < 1 or srcnode > 15:
    print("Invalid source node, range is 1 to 15")
    sys.exit()

msgBufz = {} # These are buffers for holding messages from each host

def getChecksum(inData):
    c = 0 # Our checksum is just 1 byte
    for d in inData:
        c = (c + d) % 256
    return c

def getTemplate():
    # - The idea here is to have a set of packet templates to diversify traffic patterns
    # - The decoding logic only checks the IG bit of eth.dst, so any multicast packet
    #   is fair game for holding this data.
    # - You can dynamically generate templates too, this just a POC
    arp =  b"" # ARP Request
    arp += b"\x08\x06"                 # eth.type (ARP)
    arp += b"\x00\x01"                 # arp.hw.type        -- Hardware Type: Ethernet
    arp += b"\x08\x00"                 # arp.proto.type     -- Protocol Type: IPv4
    arp += b"\x06"                     # arp.hw.size        -- Hardware Size: 6
    arp += b"\x04"                     # arp.proto.size     -- Protocol Size: 4
    arp += b"\x00\x01"                 # arp.opcode         -- Opcode: Request
    arp += b"\x00\x11\x22\x33\x44\x55" # arp.src.hw_mac     -- Source MAC Address
    arp += b"\x0a\x00\x01\x0a"         # arp.src.proto_ipv4 -- Source IP: 10.0.1.10
    arp += b"\x00\x00\x00\x00\x00\x00" # arp.dst.hw_mac     -- Target MAC Address
    arp += b"\x0a\x00\x01\x0b"         # arp.dst.proto_ipv4 -- Target IP: 10.0.1.11

    igmp =  b"" # IGMP Membership Query (General)
    igmp += b"\x08\x00"         # eth.type = ipv4
    igmp += b"\x45\xc0"         # ip dsfield, len
    igmp += b"\x00\x1c"         # ip.len 
    igmp += b"\xac\xab"         # ip.id
    igmp += b"\x00\x00\x01"     # ip.flags, ip.frag_offset, ip.ttl
    igmp += b"\x02"             # ip.proto      -- IGMP
    igmp += b"\x4e\x53"         # ip.checksum
    igmp += b"\x0a\x0a\x01\x01" # ip.src        -- 10.10.1.1
    igmp += b"\xe0\x00\x00\x01" # ip.dst        -- 224.0.0.1
    igmp += b"\x11"             # igmp.type     -- Membership query
    igmp += b"\x64"             # igmp.max_resp
    igmp += b"\xee\x9b"         # igmp.checksum
    igmp += b"\x00\x00\x00\x00" # igmp.maddr 

    ssdp = b"" # SSDP M-SEARCH template
    ssdp += b"\x08\x00"         # eth.type = ipv4
    ssdp += b"\x45\x00"         # ip dsfield, len
    ssdp += b"\x00\xc7"         # ip.len
    ssdp += b"\xac\xab"         # ip.id
    ssdp += b"\x40\x00\x01"     # ip.flags, ip.frag_offset, ip.ttl
    ssdp += b"\x11"             # ip.proto      -- UDP
    ssdp += b"\x4e\x53"         # ip.checksum
    ssdp += b"\x0a\x0a\x01\x01" # ip.src        -- 10.10.1.1
    ssdp += b"\xef\xff\xff\xfa" # ip.dst        -- 239.255.255.250
    ssdp += b"\xc7\x64"         # udp.srcport
    ssdp += b"\x07\x6c"         # udp.dstport
    ssdp += b"\x00\xb3"         # udp.length (179)
    ssdp += b"\x3a\x29"         # udp.checksum
    ssdp += b"M-SEARCH * HTTP/1.1\x0d\x0a"
    ssdp += b"HOST: 239.255.255.250:1900\x0d\x0a"
    ssdp += b"MAN: \"ssdp:discover\"\x0d\x0a"
    ssdp += b"MX: 1\x0d\x0a"
    ssdp += b"ST: urn:dial-multiscreen-org:service:dial:1\x0d\x0a"
    ssdp += b"USER-AGENT: iNNAnet xXxPlora 420.69 Z00buntu"
    ssdp += b"\x0d\x0a\x0d\x0a"

    pkttemplates = [arp,igmp,ssdp]
    return random.choice(pkttemplates)

def encodeMsg(inData,srcnode,dstnode):
    # This is the message structure, stuffed into the eth.src field
    #  ┌───────────────────── XOR Key
    #  │   ┌───────────────── Checksum
    #  │   │   ┌───────────── Routing info
    #  │   │   │   ┌───────── The 02 is the ASCII STX character
    # ┌┴─┐┌┴─┐┌┴─┐┌│─Text──┐ # Hex dump of plain text
    # │XR││CS││RR││02 62 6d│ # .bm  ┐
    # │XR││CS││RR││56 30 63│ # V0c  │
    # │XR││CS││RR││33 42 76│ # 3Bv  ├─ Base64 of "netspooky"
    # │XR││CS││RR││62 32 74│ # b2t  │
    # │XR││CS││RR││35 03 xx│ # 5..  ┘
    # └──┘└──┘└──┘└───│──│─┘
    #                 │  └─── Padding
    #                 └────── The 03 is the ASCII ETX character
    srcenc = srcnode & 0x0F
    dstenc = dstnode << 4 # shift the value to occupy the top 4 bits
    rr = dstenc | srcenc
    msgSeed = random.randrange(0,256)
    msgSeed = msgSeed & 0xFE # Ensure the bottom bit is never set
    msgBuf  = b""
    csum = getChecksum(inData)
    msgBuf += bytes([msgSeed])        # eth.src[0]
    msgBuf += bytes([msgSeed ^ csum]) # eth.src[1]
    msgBuf += bytes([( ( msgBuf[1] + csum ) % 256 ) ^ rr]) # eth.src[2]
    msgBuf += bytes([( ( msgBuf[2] + csum ) % 256 ) ^ inData[0]]) # eth.src[3]
    msgBuf += bytes([( ( msgBuf[3] + csum ) % 256 ) ^ inData[1]]) # eth.src[4]
    msgBuf += bytes([( ( msgBuf[4] + csum ) % 256 ) ^ inData[2]]) # eth.src[5]
    return msgBuf

def decodeMessage(inData):
    csum = inData[0] ^ inData[1] # eth.src[0] ^ eth.src[1]
    rr = ( ( inData[1] + csum ) % 256 ) ^ inData[2] # eth.src[2]
    srcdec = rr & 0x0F
    dstdec = rr >> 4
    # If the source node is the sending node, then messages are ignored.
    if srcdec != srcnode:
        msgBuf = b""
        msgBuf += bytes([( ( inData[2] + csum ) % 256 ) ^ inData[3]]) # eth.src[3]
        msgBuf += bytes([( ( inData[3] + csum ) % 256 ) ^ inData[4]]) # eth.src[4]
        msgBuf += bytes([( ( inData[4] + csum ) % 256 ) ^ inData[5]]) # eth.src[5]
        calcSum = getChecksum(msgBuf)
        # Checksums are calculated on the data and compared to the reported checksum
        # - If it matches, then it continues processing.
        # - This could use some work but it's a POC y'all.
        if csum == calcSum:
            if srcdec not in msgBufz.keys():
                msgBufz[srcdec] = b"" # When a new source is found, it adds to the buffer list
            if msgBuf[0] == 2: # This detects the STX (0x02) character indicating message start
                msgBufz[srcdec] = msgBuf # Adds the contents to the src's buffer in the list
            elif b"\x03" in msgBuf: # This detects the ETX (0x03) character indicating message end.
                msgBufz[srcdec] += msgBuf # Add the content to the src's buffer
                outMsg = msgBufz[srcdec][1:] # This grabs the message after STX
                outMsg = outMsg.split(b"\x03")[0] # This grabs the message before ETX
                try:
                    # Attempt to decode and print the buffer, then clear the buffer
                    print("{}: {}".format(srcdec, base64.b64decode(outMsg).decode('latin-1')))
                    msgBufz[srcdec] = b""
                except:
                    # If there's a decoding failure then clear the buffer
                    msgBufz[srcdec] = b""
            else:
                msgBufz[srcdec] += msgBuf

def makeBuffer(inData,csum):
    # This just adds the ASCII control chars to the data
    buf = b""
    buf += b"\x02" # STX
    buf += inData
    buf += b"\x03" # ETX
    return buf

def rcvMessage(inSock):
    while True:
        packet = inSock.recvfrom(65565)
        packet = packet[0]
        igbit = packet[0] & 1 # Check the bottom bit of the first byte
        if igbit:
            ethdst  = packet[0:6]
            ethsrc  = packet[6:12]
            decodeMessage(ethsrc) # Attempt to decode

def sendMessage(inData,dstnode,srcnode,inSock):
    i = 0
    padding = (len(inData) % 3)
    if padding != 0:
        randpad = bytes([random.randrange(80,255)]) # Get a random number outside the range we use
        inData += randpad*(3-padding) # Adds padding bytes if needed
    mlen = len(inData)
    # Split the buffer into three byte chunks, do the encoding, and stuff into a packet template.
    while i < mlen:
        chunk = inData[i:i+3]
        p = b"\xFF\xFF\xFF\xFF\xFF\xFF" # eth.src
        p += encodeMsg(chunk, srcnode, dstnode) # eth.dst
        p += getTemplate() # packet body
        inSock.send(p)
        i = i+3

def msgLoop(t):
    for line in sys.stdin:
        dstnode = 0
        msg = line.rstrip()
        msg = msg.encode('latin-1')
        b64msg = base64.b64encode(msg)
        csum = getChecksum(msg)
        pktbuf = makeBuffer(b64msg,csum)
        sendMessage(pktbuf,dstnode,srcnode,t)

if __name__ == "__main__":
    t = socket(AF_PACKET, SOCK_RAW) # This is the socket to transmit
    t.bind((interface, 0))
    r = socket( AF_PACKET, SOCK_RAW, ntohs(0x0003)) # This is how msgs are received
    x = threading.Thread(target=rcvMessage, args=(r,)) # Thread for receive loop
    x.start()
    y = threading.Thread(target=msgLoop, args=(t,)) # Thread for transmit loop
    y.start()
