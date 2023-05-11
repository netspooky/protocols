# Resources and References Page
This page contains links to things mentioned in my Protocol Reverse Engineering talk. Other cool links are also included for further reading.

## Protocol RE Fundamentals

- Method used by linguists to decipher unknown languages https://en.wikipedia.org/wiki/Comparative_method
- The Decipherment of Maya Script https://www.youtube.com/watch?v=YvLs3gDLCOI
- List of undeciphered writing systems https://en.wikipedia.org/wiki/Undeciphered_writing_systems
- LiveOverflow - What Is A Protocol? https://www.youtube.com/watch?v=d-zn-wv4Di8
- https://en.wikipedia.org/wiki/Morse_code
- https://en.wikipedia.org/wiki/Quadrature_amplitude_modulation
- https://en.wikipedia.org/wiki/Telephony#Digital_telephony
- https://en.wikipedia.org/wiki/Protocol_Wars
- https://en.wikipedia.org/wiki/Protocol_ossification
- https://en.wikipedia.org/wiki/Control_character
- https://en.wikipedia.org/wiki/8-bit_clean
- Encoding Mutations: A Base64 Case Study https://n0.lol/encmute/
- Info about Enron Modbus https://www.simplymodbus.ca/Enron.htm

## Protocol RE Techniques
- hyp's Protocol RE Resources Page https://github.com/scratchadams/PRE-Resources/

### Packet Analysis

- https://en.wikipedia.org/wiki/File_Transfer_Protocol#Communication_and_data_transfer
- https://en.wikipedia.org/wiki/Network_Control_Protocol_(ARPANET)
- https://wiki.wireshark.org/SnapLen.md
- PCAP File Format https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat
- Sample Captures https://wiki.wireshark.org/SampleCaptures
- https://www.netresec.com/?page=PcapFiles
- Dork: `site:cloudshark.org inurl:/collections/`
- The Wireshark Wiki https://gitlab.com/wireshark/wireshark/-/wikis/home
- Expanding Wireshark Beyond Network Interfaces https://sharkfestus.wireshark.org/sharkfest.13/presentations/NAP-11_Expanding-Wireshark-Beyond-Ethernet-and-Network-Interfaces_Kershaw-Ryan.pdf
- USB Replay https://github.com/JohnDMcMaster/usbrply
- TCP Replay https://github.com/appneta/tcpreplay
- Editcap https://www.wireshark.org/docs/man-pages/editcap.html
- tcpdump https://www.tcpdump.org/
- tshark https://www.wireshark.org/docs/man-pages/tshark.html
- termshark https://github.com/gcla/termshark
- LAN Tap https://greatscottgadgets.com/throwingstar/
- https://man7.org/linux/man-pages/man5/protocols.5.html
- SpeedGuide Ports List https://www.speedguide.net/ports.php
- https://en.wikipedia.org/wiki/Ephemeral_port
- https://en.wikipedia.org/wiki/Communication_protocol#Basic_requirements
- Identifying Timestamps - https://github.com/netspooky/notes/blob/main/re/timestamps.md 
- Ben Eater - How Do CRCs Work? https://www.youtube.com/watch?v=izG7qT0EpBw
- CRC Calculator https://crccalc.com/
- https://github.com/netspooky/notes/blob/main/re/string_representation.md 
- https://en.wikipedia.org/wiki/Type%E2%80%93length%E2%80%93value
- https://tls13.xargs.org/ - put this under Common Protocol Components TLV
- https://github.com/netspooky/xx/blob/main/examples/tls-clienthello.xx
- https://subtls.pages.dev/ See this page fetch itself, byte by byte, over TLS
- pdiff2 - https://github.com/netspooky/pdiff2
- pdiff-wasm - https://remyhax.xyz/tools/pdiffwasm/
- NetworkMiner - https://www.netresec.com/?page=NetworkMiner
- ngrep - https://github.com/jpr5/ngrep 
- binwalk - https://github.com/ReFirmLabs/binwalk 
- https://en.wikipedia.org/wiki/Protocol_pipelining
- https://portswigger.net/web-security/request-smuggling
- https://securityintelligence.com/posts/dissecting-exploiting-tcp-ip-rce-vulnerability-evilesp/
- Computerphile - Encryption and Entropy https://www.youtube.com/watch?v=8VSuwDG4bhw
- Good writeup about entropy uses and analysis https://gynvael.coldwind.pl/?id=162
- Reverse Engineering Binary Protocols to Create IPS Signatures https://medium.com/@kevin.massey1189/reverse-engineering-binary-protocols-to-create-ips-signatures-c0eb926e7a2
- Firewalls and Internet Security: Repelling the Wily Hacker http://wilyhacker.com/ (Old but gold)
- Attacking Network Protocols https://nostarch.com/networkprotocols 
- Practical Packet Analysis, 3rd Edition - https://nostarch.com/packetanalysis3
- Simple Browser Hex Calculator https://github.com/netspooky/hexcalc

### Software RE

- Practical Binary Analysis - https://nostarch.com/binaryanalysis
- https://learn.microsoft.com/en-us/cpp/mfc/windows-sockets-background?view=msvc-170
- https://www.freertos.org/FreeRTOS-Plus/FreeRTOS_Plus_TCP/FreeRTOS_TCP_API_Functions.html
- Tool for grouping imports from Windows binaries https://github.com/netspooky/importsort
- https://en.wikipedia.org/wiki/Berkeley_sockets
- Getting Started with WinDbg https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/getting-started-with-windbg
- yardenshafir/WinDbg_Scripts https://github.com/yardenshafir/WinDbg_Scripts
- Azeria Labs - Debugging with GDB https://azeria-labs.com/debugging-with-gdb-introduction/
- gef extension for GDB https://hugsy.github.io/gef/
- Visualization of a Linux sk_buff structure that holds packet data https://n0.lol/sk_buff.png or `curl -sL n0.lol/sk_buff.ans`
- remy - DOing Harm - Windows Delivery Optimization protocol RE https://remyhax.xyz/posts/do-harm/
- remy - DOing More Harm - https://remyhax.xyz/posts/do-more-harm/
- Pulling MikroTik into the Limelight - Demystifying and Jailbreaking RouterOS https://margin.re/2022/06/pulling-mikrotik-into-the-limelight/
- https://github.com/jtpereyda/boofuzz
- Simple script to send raw frames over an interface https://github.com/netspooky/uJunk/blob/main/net/sendframe.py
- https://openthread.io/platforms/co-processor
- Debug Windows Drivers - Step by Step Lab (Sysvad Kernel Mode) https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-universal-drivers--kernel-mode-
- Windows Driver Frameworks https://github.com/microsoft/Windows-Driver-Frameworks
- Windows Kernel Programming 2nd Edition https://leanpub.com/windowskernelprogrammingsecondedition
- Linux Kernel Debugging With GDB https://docs.kernel.org/dev-tools/gdb-kernel-debugging.html
- Linux Kernel Debugging: Going Beyond Printk Messages https://www.youtube.com/watch?v=m7SduY2XrKM
- Linux Kernel Module Programming Guide https://sysprog21.github.io/lkmpg/
- Monitoring and Tuning the Linux Networking Stack: Receiving Data https://blog.packagecloud.io/monitoring-tuning-linux-networking-stack-receiving-data/
- Monitoring and Tuning the Linux Networking Stack: Sending Data https://blog.packagecloud.io/monitoring-tuning-linux-networking-stack-sending-data/
- scare - Simple Configurable Assembly REPL && Emulator https://github.com/netspooky/scare

### Hardware RE

- Hardware Hacking for the Masses (and you) v2 - w/BusesCanFly https://www.youtube.com/watch?v=3YwrZQVfvm4
- https://fccid.io/
- USB-TTL Serial Cable https://www.adafruit.com/product/954
- Pulseview Logic Analyzer https://sigrok.org/wiki/PulseView
- https://1bitsquared.com/products/tigard
- https://1bitsquared.com/products/bitmagic-basic
- https://github.com/pyserial/pyserial
- https://github.com/netspooky/dissectors/blob/main/acble.lua
- https://www.sigidwiki.com/wiki/Signal_Identification_Guide
- RTL-SDR Dongle https://www.rtl-sdr.com/
- gqrx SDR software https://gqrx.dk/
- https://www.gnuradio.org/
- POCSAG Decoding https://www.bastibl.net/pocsag/
- Bluetooth Protocol RE https://github.com/Freeyourgadget/Gadgetbridge/wiki/BT-Protocol-Reverse-Engineering
- Reverse Engineering BLE Devices https://reverse-engineering-ble-devices.readthedocs.io/en/latest/
- Branch Education - How Does Bluetooth Work? https://www.youtube.com/watch?v=1I1vxu5qIUM
- FreqyXin - The Basics of Breaking BLE https://www.youtube.com/watch?v=X2ARyfjzxhY
- FreqyXin - The Basics of Breaking BLE Pt. 2 https://www.youtube.com/watch?v=IVwqMDQ6Ydo
- notpike/The-Fonz - TouchTunes Jukebox Sniffer/Client https://github.com/notpike/The-Fonz

### Specifications

- HTTP 1.0 RFC https://datatracker.ietf.org/doc/html/rfc1945
- 2 byte remote DOS in telnetd https://pierrekim.github.io/blog/2022-08-24-2-byte-dos-freebsd-netbsd-telnetd-netkit-telnetd-inetutils-telnetd-kerberos-telnetd.html
- Telnet RFC 854 https://www.rfc-editor.org/rfc/rfc854.html
- CHIP-8 Bug https://www.da.vidbuchanan.co.uk/blog/bggp3.html
- Endianness Bug https://tmpout.sh/2/3.html

## Documenting Your Findings

- Creating A Wireshark Dissector In Lua https://mika-s.github.io/wireshark/lua/dissector/2017/11/04/creating-a-wireshark-dissector-in-lua-1.html
- List of Lua dissectors https://wiki.wireshark.org/Contrib
- Wireshark Lua Docs https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html
- Writing a Wireshark dissector to parse data embedded in ICMP headers https://medium.com/@kevin.massey1189/writing-a-wireshark-dissector-to-parse-data-embedded-in-icmp-headers-1f039cd4072d
- https://kaitai.io/
- https://github.com/netspooky/xx
- https://github.com/Synide/010-Editor-Templates
