from socket import *

# ETHSCROLL.PY -- Should work on most routers

interface = "eth0" # Your network interface

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
    framee =  b"\xFF\xFF\xFF\xFF\xFF\xFF" # eth.dst
    framee += b"\x42\x4f\x4f\x21\x21\x21" # eth.src
    framee += b"\x00\x00" # eth.type
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
