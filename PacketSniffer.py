import socket
import struct

# create a raw socket and bind it to the public network interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind(('0.0.0.0', 0))

# receive all incoming packets
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

while True:
    # receive a packet and extract its header
    packet = s.recvfrom(65565)[0]
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    # extract the source and destination IP addresses
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    # print out some information about the packet
    print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
    print(f"Packet Data: ")
    print(f"\t {packet}")