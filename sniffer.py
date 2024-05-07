#!/bin/python
import os, socket,shutil
import scapy.all as sc

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_RESET = "\033[0m"
COLOR_MAGENTA = "\033[35m"
COLOR_YELLOW = "\033[33m"
COLOR_CYAN = "\033[36m"

counter=0
def proto_name_by_num(proto_num): # function to get the protocol name from the protocol number
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Not Found"
print(COLOR_GREEN)
print((" Network Interfaces Present ").center(shutil.get_terminal_size().columns, "="))
print(COLOR_RESET)
print(sc.conf.ifaces)
# TD - *add feature of filtering packets - showing specific protocols or packets from specific IP/to IP before showing result. And allow a normal mode of printing result where it just captures everything.
# TD How do we count the serial number? -> done
# Show a substring of the payload ->done
# I want to convert payload to ascii -> done
# Colorise the OP -> done
# TD-> Can we capture traffic from all interfaces?? ??
# SHowing info like in wireshark.. it is contained in the "type" section of the layer, but how to translate it into its meaning? -> I believe we will need to study the packet types for protocols like ARP and ICMP, we get the type in the packet, but it will have to be mapped.
# TC-> Capturing VM traffic
# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages - ICMP 
# Show port number, flags?
# Data packets - green; management pkts - blue. HTTP packets - red
def highlight(text, color_code):
    return f"\033[{color_code}m{text}\033[0m"

def display_packets(pkt, context="sniff"):
    if context=="sniff":
        global counter
        counter+=1
    try:
        protocol=proto_name_by_num(pkt.proto) 

    except AttributeError:
        try:
            protocol=sc.conf.l3types[pkt['Ethernet'].type].__name__
        except:
            try:
                protocol=sc.conf.l2types[pkt['Ethernet'].type].__name__
            except:
                protocol="Error"

    try:
        my_ip = sc.get_if_addr(sc.conf.iface)
        try:
            my_mac= sc.get_if_hwaddr(sc.conf.iface)
        except:
            my_mac=""
    except:
        my_ip = ""
    try:
        src=pkt['IP'].src
        dst=pkt['IP'].dst

    except (AttributeError, IndexError):
        try:
            src=pkt['Ethernet'].src
            dst=pkt['Ethernet'].dst
        except:
            src='-'
            dst='-'
    if src == my_ip or src == my_mac:
        dir = "->"
    elif dst == my_ip or dst == my_mac:
        dir = "<-"
    else:
        dir=""
    try:
        length=pkt.len
    except AttributeError:
        length=0
   
    try:
        payload=pkt.load
      
    except:
        if protocol=='ARP':
            if pkt['ARP'].op==1:
                # https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit
                print(f"\033[48;5;6;38;5;0m{str(counter).ljust(10)}{dir.ljust(5)}{protocol.ljust(10)}{src.ljust(20)}{dst.ljust(20)}{str(length).ljust(10)}", end="")
                print(f"Who has {pkt['ARP'].pdst}?".ljust(shutil.get_terminal_size().columns - 75), end="")
                print(f"\033[0m")
            elif pkt['ARP'].op==2:
                print(f"\033[48;5;6;38;5;0m{str(counter).ljust(10)}{dir.ljust(5)}{protocol.ljust(10)}{src.ljust(20)}{dst.ljust(20)}{str(length).ljust(10)}{pkt['ARP'].psrc} is at {pkt['Ethernet'].src.ljust(shutil.get_terminal_size().columns - 75)}", end="")
                print(f"\033[0m")
        
            else:
                print(f"\033[48;5;6;38;5;0m{str(counter).ljust(10)}{dir.ljust(5)}{protocol.ljust(10)}{src.ljust(20)}{dst.ljust(20)}{str(length).ljust(10)}\033[0m", end="")
        else:
                print(f"{str(counter).ljust(10)}{dir.ljust(5)}{protocol.ljust(10)}{src.ljust(20)}{dst.ljust(20)}{str(length).ljust(10)}")
    else:
        if protocol=="ICMP":
            print(f"\033[48;5;6;38;5;0m{str(counter).ljust(10)}{dir.ljust(5)}{protocol.ljust(10)}{src.ljust(20)}{dst.ljust(20)}{str(length).ljust(10)}{''.join([chr(byte) if 31 < byte < 127 else '·' for byte in payload[:shutil.get_terminal_size().columns - 75]]).ljust(100)}\033[0m")
        if pkt['TCP']:
            if pkt['TCP'].dport==80 or pkt['TCP'].sport==80:
                print(f"\033[48;5;9;38;5;0m{str(counter).ljust(10)}{dir.ljust(5)}{protocol.ljust(10)}{src.ljust(20)}{dst.ljust(20)}{str(length).ljust(10)}{''.join([chr(byte) if 31 < byte < 127 else '·' for byte in payload[:shutil.get_terminal_size().columns - 75]]).ljust(100)}\033[0m")
        else:
            print(f"\033[48;5;10;38;5;0m{str(counter).ljust(10)}{dir.ljust(5)}{protocol.ljust(10)}{src.ljust(20)}{dst.ljust(20)}{str(length).ljust(10)}{''.join([chr(byte) if 31 < byte < 127 else '·' for byte in payload[:shutil.get_terminal_size().columns - 75]]).ljust(100)}\033[0m")
    
        
def capture_packets(interface):
    global counter
    print(COLOR_MAGENTA)
    print("Press Ctrl+C to stop capturing.")
    print(COLOR_RESET)
    print(COLOR_YELLOW)
    print("Sr. No.".ljust(15), "Protocol".ljust(10), "Source".ljust(20), "Destination".ljust(20), "Length".ljust(10), "Payload".ljust(100), sep='')
    print(COLOR_RESET)
    pkt_capture = sc.sniff(iface=interface, prn=display_packets)
    while(True):
        print(COLOR_MAGENTA)
        print("\nTo inspect a packet in detail, enter the Index of that packet.\nTo apply a filter, enter -1.\nTo quit, enter 0.\nChoice: ",end='')
        print(COLOR_RESET, end='')
        ch2=int(input())
        if ch2==0: 
            exit(0)
        elif ch2==-1:
            print(COLOR_MAGENTA)
            print("\nChoose filtering criteria - Source IP/MAC(S), Destination IP/MAC(D), Protocol type(P): ", end="")
            print(COLOR_RESET, end='')
            ch3=input()
            if ch3.lower()=='s':
                    src_list=set()
                    for pkt in pkt_capture:
                        try:
                            src_list.add(pkt['IP'].src)
                        except:
                            src_list.add(pkt['Ethernet'].src)    
                    src_list=list(src_list)
                    print(COLOR_YELLOW)
                    print("Source addresses found in the capture:\n")
                    for i, address in enumerate(src_list):
                        print(f"{i+1}\t{address}")
                    print(COLOR_RESET, end='')
                    print(COLOR_MAGENTA)
                    print("Enter the source IP or MAC address you want to filter by: ",end="")
                    print(COLOR_RESET, end='')
                    filter_by_src=src_list[int(input())-1]
                    print(COLOR_YELLOW)
                    print("Sr. No.".ljust(10), "Protocol".ljust(10), "Source".ljust(20), "Destination".ljust(20), "Length".ljust(10), "Payload/Info".ljust(100), sep='')
                    print(COLOR_RESET)
                    for i,pkt in enumerate(pkt_capture):
                        try:
                            src=pkt['IP'].src
                        except: 
                            src=pkt['Ethernet'].src
                        finally:
                            if filter_by_src==src:
                                counter=i+1
                                display_packets(pkt, "show")
            elif ch3.lower()=='d':
                dst_list=set()
                for pkt in pkt_capture:
                    try:
                        dst_list.add(pkt['IP'].dst)
                    except:
                        dst_list.add(pkt['Ethernet'].dst)    
                dst_list=list(dst_list)
                print(COLOR_YELLOW)
                print("Destination addresses found in the capture:\n")
                for i, address in enumerate(dst_list):
                    print(f"{i+1}\t{address}")
                print(COLOR_RESET, end='')
                print(COLOR_MAGENTA)
                print("Enter the destination IP or MAC address you want to filter by: ",end="")
                print(COLOR_RESET, end='')
                filter_by_dst=dst_list[int(input())-1]
                print(COLOR_YELLOW)
                print("Sr. No.".ljust(10), "Protocol".ljust(10), "Source".ljust(20), "Destination".ljust(20), "Length".ljust(10), "Payload".ljust(100), sep='')
                print(COLOR_RESET)
                for i,pkt in enumerate(pkt_capture):
                    try:
                        dst=pkt['IP'].dst
                    except: 
                        dst=pkt['Ethernet'].dst
                    finally:
                        if filter_by_dst==dst:
                            counter=i+1
                            display_packets(pkt, "show")
            elif ch3.lower()=='p':
                protocol_list=set()
                for pkt in pkt_capture:
                    try:
                        protocol=proto_name_by_num(pkt.proto) 

                    except AttributeError:
                        try:
                            protocol=sc.conf.l3types[pkt['Ethernet'].type].__name__
                        except:
                            try:
                                protocol=sc.conf.l2types[pkt['Ethernet'].type].__name__
                            except:
                                protocol="error"
                    finally:
                        if protocol!="error":
                            protocol_list.add(protocol)
                        
                protocol_list=list(protocol_list)
                print(COLOR_YELLOW)
                print("Protocol types found in the capture:\n")
                for i, proto in enumerate(protocol_list):
                    print(f"{i+1}\t{proto}")
                print(COLOR_RESET, end='')
                print(COLOR_MAGENTA)
                print("Enter the protocol you want to filter by: ",end="")
                print(COLOR_RESET, end='')
                filter_by_protocol=protocol_list[int(input())-1]
                print(COLOR_YELLOW)
                print("Sr. No.".ljust(10), "Protocol".ljust(10), "Source".ljust(20), "Destination".ljust(20), "Length".ljust(10), "Payload".ljust(100), sep='')
                print(COLOR_RESET)
                for i,pkt in enumerate(pkt_capture):
                    try:
                        protocol=proto_name_by_num(pkt.proto) 

                    except AttributeError:
                        try:
                            protocol=sc.conf.l3types[pkt['Ethernet'].type].__name__
                        except:
                            try:
                                protocol=sc.conf.l2types[pkt['Ethernet'].type].__name__
                            except:
                                protocol="error"
                    finally:
                        if filter_by_protocol==protocol:
                            counter=i+1
                            display_packets(pkt, "show")
        else:
            try:
                print(COLOR_GREEN)
                print((f" Detailed view of packet #{ch2} ").center(shutil.get_terminal_size().columns, "="))
                print(COLOR_RESET)
                pkt_capture[ch2-1].show()
                try:
                    payload=pkt_capture[ch2-1].load
                except AttributeError:
                    pass
                else:
                    print("Load decoded as ASCII:")
                    ascii_representation = ''.join([chr(byte) if 31 < byte < 127 else '·' for byte in payload])
                    print(COLOR_CYAN)
                    print(ascii_representation)
                    print(COLOR_RESET)
                print(COLOR_MAGENTA)
                print("To return to packets list, enter 'R': ", end='')
                print(COLOR_RESET, end='')
                go_back=input()
                if go_back.upper()=="R":
                    print(COLOR_YELLOW)
                    print("Sr. No.".ljust(10), "Protocol".ljust(10), "Source".ljust(20), "Destination".ljust(20), "Length".ljust(10), "Payload".ljust(100), sep='')
                    print(COLOR_RESET)
                    for i in range(len(pkt_capture)):
                        counter=i+1
                        display_packets(pkt_capture[i], "show")
                else:
                    exit(0)

            except IndexError:
                print("That packet does not exist!")

def filter_packets(pkt):
    print("Choose type of filter - Source IP/MAC, Destination IP/MAC, Protocol type(P)")
    ch3=input()
    if ch3.lower()=='s':
        try:
            src=pkt['IP'].src
        except: 
            src= pkt['Ethernet'].src

    elif ch3.lower()=='d':
        # filter on dest
        print("")

    elif ch3.lower()=='p':
        # filter on type
        print("")

print(COLOR_MAGENTA)
print("Enter the index of the interface to capture: ", end='')
print(COLOR_RESET, end='')
ch=int(input())
if ch==0:
    exit(0)
else:
    try:
        print(f"Capturing traffic from {sc.dev_from_index(ch)}...")
    except:
        print("Interface does not exist. Try again or choose 0 to quit.")
    else:
        if os.geteuid()!=0:
            print("This script must be run as sudo.")
            exit(0)
        capture_packets(sc.dev_from_index(ch))

