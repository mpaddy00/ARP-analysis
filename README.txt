Enter custom file (which needs to be in the same folder) by typing 'y' then the file name. Incorrectly 
typing the name will result in an error.

otherwise type anything else to have the program run the pcap I captured and included 

Part A(1): screenshot of arp exchange is included in the folder titled 'screenshotARP.png'

Part B(3):  Based on the ARP exchange my computer's IP address is: 10.1.148.121 
and the MAC address is: 14 4f 8a e0 d7 c4

I figured this out by first looking at the request which was asking who is at 10.1.148.121 then I looked at the response
of the sender which lined up with the target IP/MAC of the asker. Thus, that was what the IP and MAC address were.

Part B program logic: The program is fairly simple. The packet is broken down into a structure that is readable and 
there is a boolean to check if the packet is an ARP. Also a function to format an integer into a ip address.
The flow class simply prints out all the contents of the packet and keeps track of the packet number we are on.
The i/o is pretty self explanatory.
The driver iterates over every packet in the pcap file and if it is an ARP packet it increases the ARP counter
by 1. If it is an ARP packet and not an ARP probe and no packet has been printed yet. Then print the packet
request. Then once that is finished the for loop keeps iterating until it finds an ARP packet with 
the response opcode. Then prints that. The program will keep counting ARP packets after that, but will not
print them in line with the requirements set out by the assignment. 