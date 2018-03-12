#!/usr/bin/python

import dpkt
import sys
import socket
import traceback
import getopt

def get_ipn(ip):
    return socket.inet_pton(socket.AF_INET, ip)

ip1='188.227.158.1'
ip2='188.227.159.1'
sport=80
dport=17917

pinglist_file = 'pinglist3.txt'
il_files_reverse = ['il/trace_20170623-131652.pcap', 'il/trace_20170624-131652.pcap', 'il/trace_20170625-131945.pcap']

il_files_forward = ['il/trace_20170626-132057.pcap', 'il/trace_20170627-132100.pcap']

cz_files_reverse = ['cz/trace_20170623-222737.pcap', 'cz/trace_20170624-214611.pcap', 'cz/trace_20170625-214611.pcap']
cz_files_forward = ['cz/trace_20170626-145623.pcap', 'cz/trace_20170627-145628.pcap']


mapping1 = ((cz_files_forward, il_files_forward), (get_ipn(ip1), get_ipn(ip2)))
mapping2 = ((cz_files_reverse, il_files_reverse), (get_ipn(ip2), get_ipn(ip1)))



def d(message):
    pass
#    print(message)

def mac_addr(address):
    def hex_dump(s):
        return ':'.join('%02x' % ord(b) for b in s)

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

def read_pcap(f):
    try:
        print("Opening file %s" % (f))
        pcapf = open(f, 'rb')
        pcap = dpkt.pcap.Reader(pcapf)
        for ts, p in pcap:
            res = analyze_packet(ts, p)
            if res:
                yield res
    except Exception as ex:
        print("Exception while reading %s" % f)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_tb(exc_traceback)
    finally:
        pcapf.close()


def resolve(res, correct_ip):
    """
    returns (src_ipn, code)
    --- code 0 = no data, 1 = correct dest ip, 2 = incorrect dest ip, >2 error/data mismatch
    """
    (src, dst) = res
    for i in (0,1):
        if dst == correct_ip:
            return (src, 1)
        else:
            return (src, 2)
    return (src, 255)


def merge(table, result, i):
    if result[0] in table:
        if table[result[0]][i] < result[1]:
            table[result[0]][i] = result[1]
    #else:
    #    print("Unknown dst IP:" % inet_to_str(res[1]))


def analyze_mapping(mapping, result_table, pinglist):
    (files_pairs, ipn_pairs) = mapping

    for i in (0,1):
        for f in files_pairs[i]:
            pcap_restab = {k:False for k in pinglist}
            pcap_mismatch = 0
            for r in read_pcap(f):
                if r[0] in pcap_restab:
                    pcap_restab[r[0]] = True
                else:
                    pcap_mismatch +=1
                merge(result_table, resolve(r, ipn_pairs[i]), i)
            pcap_hit = 0
            pcap_loss = 0
            for k in pcap_restab:
                if pcap_restab[k] == True:
                    pcap_hit += 1
                else:
                    pcap_loss += 1
            print("pcap hit=%d, loss=%d, missmatch=%d" %(pcap_hit, pcap_loss, pcap_mismathc))


def gen_report(result_table1, result_table2):
    def get_trace(rt1, rt2, k):
        return (rt1[k][0], rt1[k][1], rt2[k][0], rt2[k][1])

    def test_trace(trace, tf):
        for i in (0,1,2,3):
            if tf(trace[i]):
                return True
        return False

    def is_norov(trace):
        return test_trace(trace, lambda x: x == 2)

    def is_unknown(trace):
        return test_trace(trace, lambda x: x == 0)

    def is_rov(trace):
        if trace == (1,1,1,1):
            return True
        if is_norov(trace):
            return False
        hit=0
        for i in (0,1,2,3):
            if trace[i] == 1:
                hit+=1
        if hit >= 2:
            return True
        return False
 
    rov = 0
    norov = 0
    unknown = 0
    mismatch = 0
    for k in result_table1:
        t = get_trace(result_table1, result_table2, k)
        if is_rov(t):
            rov+=1
        elif is_norov(t):
            norov+=1
        elif is_unknown(t):
            unknown+=1
        else:
            mismatch+=1

    print('rov=%d norov=%d unknown=%d mismatch=%d' % (rov, norov, unknown, mismatch))


def main():
    pinglist = readpinglist(pinglist_file)
    result_table1 = {k: [0,0] for k in pinglist}
    result_table2 = result_table1.copy()

    analyze_mapping(mapping1, result_table1, pinglist)
    analyze_mapping(mapping2, result_table2, pinglist)

    gen_report(result_table1, result_table2)


if __name__ == '__main__':
    main()

