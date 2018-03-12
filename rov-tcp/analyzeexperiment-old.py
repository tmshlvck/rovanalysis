#!/usr/bin/python

import dpkt
import sys
import socket
import traceback
import getopt

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

def readpinglist(fn):
    with open(fn, 'r') as f:
        for l in f:
            ln = l.strip()
            if ln:
                yield socket.inet_pton(socket.AF_INET, ln)

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

def read_pcap(f, resultmap, ip1n, ip2n):
    diffip=0
    try:
        print "Opening file %s with ip1=%s ip2=%s" % (f, inet_to_str(ip1n), inet_to_str(ip2n))
        pcapf = open(f, 'rb')
        pcap = dpkt.pcap.Reader(pcapf)
        for ts, p in pcap:
            res = analyze_packet(ts, p)
            if res:
		if not (res[0] in resultmap):
                    d("Warn: Unexpected correct reply from: %s" % inet_to_str(res[0]))
		    diffip += 1
                    if not (res[0] in resultmap):
                        resultmap[res[0]] = 0
                if res[1] == ip1n:
                    #d("%s %d |=1" % (inet_to_str(res[0]), resultmap[res[0]]))
                    resultmap[res[0]] |= 1
                elif res[1] == ip2n:
                    #d("%s %d |=2" % (inet_to_str(res[0]), resultmap[res[0]]))
                    resultmap[res[0]] |= 2
                else:
                    print "Unknown dst IP:" % inet_to_str(res[1])
    except Exception as ex:
        print "Exception while reading %s" % f
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback)
    finally:
        pcapf.close()

    return (diffip, )


def count_summaries(rl, stats):
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

#        if rl[k] == 1 or rl[k] == 2:
#            print "%s: %d" % (inet_to_str(k), rl[k])

    print "\nSummary:\ndests=%d\ndiffip=%d\nnoreply=%d\nboth=%d\nhit1=%d\nhit2=%d" % (len(rl.keys()), stats[0], noreply, both, hit1, hit2)

def cross_check(rl1, rl2):
    crossresult={}

    for k in set(rl1.keys()+rl2.keys()):
        if not (k in rl2):
            rl2[k] = 0
        if not (k in rl1):
            rl1[k] = 0
        crossresult[k] = (rl1[k], rl2[k])

    return crossresult

def cross_check_reverse(rl1, rl2, rrl1, rrl2):
    crossresult={}

    for k in set(rl1.keys()+rl2.keys()):
        if not (k in rl2):
            rl2[k] = 0
        if not (k in rl1):
            rl1[k] = 0
 
        if rl1[k] == 1 and k in rrl1 and rrl1[k] == 1 and rl2[k] == 2 and k in rrl2 and rrl2[k] == 2 :
            crossresult[k] = (4,4)
        else:
            crossresult[k] = (rl1[k]|(rrl1[k] if k in rrl1 else 0), rl2[k]|(rrl2[k] if k in rrl2 else 0))

        print 'k=%s rl1[k]=%d rl2[k]=%d crossresult[k]=%s' % (inet_to_str(k), rl1[k], rl2[k], str(crossresult[k]))
    return crossresult




def print_crossresult(r):
    noreply=0
    both1=0
    both2=0
    roa=0
    roaconfirm=0
    roaincomplete=0
    inverse=0
    weird=0

    for k in r:
        if r[k][0] == 0 and r[k][1] == 0:
            noreply += 1
        elif r[k][0] == 3 and r[k][1] == 0:
            both1 += 1
        elif r[k][0] == 0 and r[k][1] == 3:
            both2 += 1
        elif r[k][0] == 1 and r[k][1] == 2:
            roa+=1
        elif (r[k][0] == 1 and r[k][1] == 0) or (r[k][0] == 0 and r[k][1] == 2):
            roaincomplete+=1
        elif r[k][0] == 2 and r[k][1] == 1:
            inverse+=1
        elif r[k][0] == 4 or r[k][1] == 4:
            roaconfirm += 1
        else:
            weird+=1
            print "Weird: %s -> (%d, %d)" % (inet_to_str(k), r[k][0], r[k][1])

    print "Cross-check result:\ndests=%d\nnoreply=%d\nboth vantage point 1=%d\nboth vantage point 2=%d\nroa-compliant static=%d\nroa-compliant confirmed=%d\nroa-compliant, path dropped=%d\nroa-inverted static=%d\nnoise/random routing=%d" % (len(r.keys()), noreply, both1, both2, roa, roaconfirm, roaincomplete, inverse, weird)

def main():
    ip1n = socket.inet_pton(socket.AF_INET, ip1)
    ip2n = socket.inet_pton(socket.AF_INET, ip2)

    reverse = False
    rl1 = None
    rl2 = None
    rrl1 = None
    rrl2 = None
    f1 = None
    f2 = None

    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:f:s:r" )
    except getopt.GetoptError as err:
        print str(err)
        sys.exit(2)

    for o, a in opts:
        if o == '-p':
            pinglist = a
            rl1 = {k: 0 for k in readpinglist(pinglist)}
            rl2 = rl1.copy()
            rrl1 = rl1.copy()
            rrl2 = rl1.copy()
        elif o == '-r':
            reverse=True

        elif o == '-f':
            f1 = a

        elif o == '-s':
            f2 = a

            stats1 = read_pcap(f1, (rrl1 if reverse else rl1), (ip2n if reverse else ip1n), (ip1n if reverse else ip2n))
            stats2 = read_pcap(f2, (rrl2 if reverse else rl2), (ip2n if reverse else ip1n), (ip1n if reverse else ip2n))

#           print "PCAP1:"
#           count_summaries(rl1, stats1)

#           print "PCAP2:"
#           count_summaries(rl2, stats2)

#    crossresult = cross_check(rl1, rl2)
    crossresult = cross_check_reverse(rl1, rl2, rrl1, rrl2)
    print_crossresult(crossresult)

if __name__ == '__main__':
    main()

