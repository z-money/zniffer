import socket,struct,binascii
import argparse

parser = argparse.ArgumentParser(description="Sniff some packets.")
parser.add_argument('--destination', dest='destination',
        help='if you just want to listen packets headed to one ip address',
        default = None)
parser.add_argument('--source', dest='source',
        help='if you just want to listen to packets coming from one ip address',
        default = None)
parser.add_argument('--protocl', dest='protocol',
        help='if you just want to listen to packets with a certain protocol,\
        8 is BGP, I need to look up the others',
        default = None)

args = parser.parse_args()
print(args.destination)
print(args.source)


def eth_addr(addr):
    '''
    Gets the MAC address into a human readable format
    '''
    mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (addr[0],addr[1],addr[2],addr[3],addr[4],addr[5])
    return mac

def get_ip(s):
    '''
    Gets the IP address into a human readable format
    '''
    return '.'.join([str(symbol) for symbol in s])


# create our socket
s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))

while True:
    packet_dict = {}
    # listen for packets
    packet = s.recvfrom(66565)
    
    # store the raw packet, so you could go back
    # through old packets, if you wanted different info,
    # or if something was corrupt
    packet_dict["raw_packet"] = packet
    
    # length of our ethernet frame header
    ethLen = 14
    ethHeader = packet[0][:ethLen]
    ethHeader = struct.unpack("!6s6sH",ethHeader)
    packet_dict["destMac"] = eth_addr(ethHeader[0])
    packet_dict["sourceMac"] = eth_addr(ethHeader[1])
    # TODO: research more about this field
    packet_dict["protocol"] = socket.ntohs(ethHeader[2])

    # check that this packet has the correct protocl
    # TODO: add the ability to filter by MAC
    if(args.protocol == None or packet_dict["protocol"] == args.protocol):
        # grab the source and destination IP
        src, target = struct.unpack('!4s4s', packet[0][26:34])
        packet_dict["sourceIp"] = get_ip(src)
        packet_dict["destinationIp"] = get_ip(target)
        
        # check that we're interested in packets related
        # to this source and destination
        if((args.source == None or packet_dict["sourceIp"] == args.source) and
                (args.destination == None or packet_dict["destinationIp"] == args.destination)):
            # grab the data
            # TODO: get a better theoretical understanding of this
            # it works, but I don't know exactly when it's going to pad
            # or what would happen if the payload needed to be segmented
            # over several packets
            payload = packet[0][66:]
            payload = struct.unpack("!"+str(len(payload))+"s",payload)
            
            # decode it, if we can
            try:
                packet_dict["payload"] = payload[0].decode()
            except Exception:
                packet_dict["payload"] = payload[0]
            
            # print it out
            print(packet_dict)
