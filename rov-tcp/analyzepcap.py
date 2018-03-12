#!/usr/bin/python

import dpkt
import sys
import socket
import traceback

ip1='188.227.158.1'
ip2='188.227.159.1'
sport=80
dport=17917


def d(message):
    pass
#    print message

def hex_dump(s):
    return ':'.join('%02x' % ord(b) for b in s)

def mac_addr(address):
    return hex_dump(address)

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def analyze_packet(ts, p):
    eth = dpkt.ethernet.Ethernet(p)
    d('Ethernet Frame: %s %s %d' % (mac_addr(eth.src), mac_addr(eth.dst), eth.type))

    if not isinstance(eth.data, dpkt.ip.IP):
        d('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        return None

    ip = eth.data
    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
    d('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
        (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

    if not isinstance(ip.data, dpkt.tcp.TCP):
        d('Non-TCP packet type not supported %s\n' % ip.data.__class__.__name__)
        return None

    tcp = ip.data
    if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK) and \
	tcp.sport == sport and tcp.dport == dport:
        d("SYN+ACL reply sport=%d dport=%d" % (tcp.sport, tcp.dport))
        return (ip.src, ip.dst)

    return None


def readpinglist(fn):
    with open(fn, 'r') as f:
        for l in f:
            ln = l.strip()
            if ln:
                yield socket.inet_pton(socket.AF_INET, ln)

def main():
    rl = {k: 0 for k in readpinglist(sys.argv[2])}

    ip1n = socket.inet_pton(socket.AF_INET, ip1)
    ip2n = socket.inet_pton(socket.AF_INET, ip2)

    diffip=0
    pkts=0
    try:
        pcapf = open(sys.argv[1], 'rb')
        pcap = dpkt.pcap.Reader(pcapf)
        for ts, p in pcap:
            pkts += 1
            res = analyze_packet(ts, p)
            if res:
		if not res[0] in rl:
                    print "Warn: Unexpected correct reply from: %s" % inet_to_str(res[0])
		    diffip += 1
                    continue
                if res[1] == ip1n:
                    rl[res[0]] |= 1
                elif res[1] == ip2n:
                    rl[res[0]] |= 2
                else:
                    print "Unknown dst IP:" % inet_to_str(res[1])
    except Exception as ex:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print("*** print_tb:")
        traceback.print_tb(exc_traceback)
    finally:
        pcapf.close()

    noreply=0
    both=0
    hit1=0
    hit2=0

    for k in rl.keys():
        if rl[k] == 0:
            noreply+=1
        elif rl[k] == 3:
            both += 1
        elif rl[k] == 1:
            hit1 += 1
        elif rl[k] == 2:
            hit2 += 1

        if rl[k] == 1 or rl[k] == 2:
            print "%s: %d" % (inet_to_str(k), rl[k])

    print "\nSummary:\npkts=%d\ndsts=%d\ndiffip=%d\nnoreply=%d\nboth=%d\nhit1=%d\nhit2=%d" % (pkts, len(rl.keys()), diffip, noreply, both, hit1, hit2)

if __name__ == '__main__':
    main()
