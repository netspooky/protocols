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
