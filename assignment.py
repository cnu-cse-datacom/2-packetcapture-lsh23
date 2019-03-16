import socket
import struct

def start_capture():
    print("<<<<<<Packet Capture Start>>>>>>")

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x" + ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)


def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header = struct.unpack("!1c1c2s2s2s1c1c2s4c4c", data)
    ip_version = int(ip_header[0].hex()[0],16) 
    ip_Length = int(ip_header[0].hex()[1],16)
    differentiated_service_codepoint = ip_header[1].hex()[0]
    explicit_congestion_notification = ip_header[1].hex()[1]
    total_length = int(ip_header[2].hex(),16)
    identification = int(ip_header[3].hex(),16)
    flags = "0x" + ip_header[4].hex()
    reserved_bit =  ip_header[4].hex()[0]
    not_fragments = ip_header[4].hex()[1]
    fragments = ip_header[4].hex()[2]
    fragments_offset = ip_header[4].hex()[3]
    Timetolive = int(ip_header[5].hex(),16)
    protocol = int(ip_header[6].hex(),16)
    header_checksum = "0x" + ip_header[7].hex()
    source_ip_address = convert_ip_address(ip_header[8:12])
    dest_ip_address = convert_ip_address(ip_header[12:16])
    
    print("======ip header======")
    print("ip_version:", ip_version)
    print("ip_Length:", ip_Length)
    print("differentiated_service_codepoint:", differentiated_service_codepoint)
    print("explicit_congestion_notification:", explicit_congestion_notification)
    print("total_length:", total_length)
    print("identification:", identification)
    print("flags:", flags)
    print(">>>reserved_bit:", reserved_bit)
    print(">>>not_fragments:", not_fragments) 
    print(">>>fragments:", fragments)
    print(">>>fragments_offset:", fragments_offset)
    print("Time to live:", Timetolive) 
    print("protocol:",protocol)
    print("header checksum:",header_checksum)
    print("source_ip_address:", source_ip_address)
    print("dest_ip_address:", dest_ip_address)

    return protocol;

def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(str(int(i.hex(),16)))
    ip_addr = ".".join(ip_addr)
    return ip_addr

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!2s2s4s4s2s2s2s2s", data)
    src_port = int(tcp_header[0].hex(),16) 
    dec_port = int(tcp_header[1].hex(),16)
    seq_num = int(tcp_header[2].hex(),16)
    ack_num = int(tcp_header[3].hex(),16)
    header_len = int(tcp_header[4].hex()[0],16)
    flags = "0x" + tcp_header[4].hex()[1:4]
    flag_bi = bin(int(flags,16))[2:].zfill(12)
    reserved = int(flag_bi[0:3])
    nonce = flag_bi[4]
    cwr = flag_bi[5]
    urgent = flag_bi[6]
    ack = flag_bi[7]
    push = flag_bi[8]
    reset = flag_bi[9]
    syn = flag_bi[10]
    fin = flag_bi[11]
    window_size_value = int(tcp_header[5].hex(),16)
    checksum = "0x"+ tcp_header[6].hex()
    urgent_pointer = int(tcp_header[7].hex(),16)


    print("======tcp_header======")
    print("src_port:", src_port)
    print("dec_port:", dec_port)
    print("seq_num:",seq_num)
    print("ack_num:",ack_num)
    print("flags:", flags)
    print(">>>reserved:",reserved)
    print(">>>nonce:", nonce)
    print(">>>cwr:", cwr)
    print(">>>urgent:",urgent)
    print(">>>ack:",ack)
    print(">>>push:",push)
    print(">>>reset:",reset)
    print(">>>syn:",syn)
    print(">>>fin:",fin)
    print("window_size_value:",window_size_value)
    print("checksum:",checksum)
    print("urgent_pointer:", urgent_pointer)

def parsing_udp_header(data):
    udp_header = struct.unpack("!2s2s2s2s", data)
    src_port = int(udp_header[0].hex(),16) 
    dec_port = int(udp_header[1].hex(),16)
    leng = int(udp_header[2].hex(),16)
    header_checksum = "0x"+ udp_header[3].hex()


    print("======udp_header======")
    print("src_port:", src_port)
    print("dec_port:", dec_port)
    print("leng:",leng)
    print("header_checksum:",header_checksum)

recv_socket = socket.socket(socket.AF_PACKET,socket.SOCK_RAW, socket.ntohs(0x800))

while True:
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    protocol = parsing_ip_header(data[0][14:34])
    if(protocol==6):
        parsing_tcp_header(data[0][34:54])
    if(protocol==17):
        parsing_udp_header(data[0][34:42])
