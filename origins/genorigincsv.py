#!/usr/bin/env python3

import sys
from mrtparse import *
import csv



def prerror(m):
    print('%s: %s' % (MRT_ERR_C[m.err], m.err_msg))
    if m.err == MRT_ERR_C['MRT Header Error']:
        buf = m.buf
    else:
        buf = m.buf[12:]
    s = ''
    for i in range(len(buf)):
        if isinstance(buf[i], str):
            s += '%02x ' % ord(buf[i])
        else:
            s += '%02x ' % buf[i]

        if (i + 1) % 16 == 0:
            print('    %s' % s)
            s = ''
        elif (i + 1) % 8 == 0:
            s += ' '
    if len(s):
        print('    %s' % s)


def strip_aspath(asp):
#    return asp

    if asp[-1] > 397212 and len(asp) > 1:
        return strip_aspath(asp[:-1])
    else:
        return asp

def get_aspaths(m):
    if ( m.subtype == TD_V2_ST['RIB_IPV4_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV4_MULTICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_MULTICAST']):

        pref = "%s/%d" % (m.rib.prefix, m.rib.plen)

        for entry in m.rib.entry:
            for attr in entry.attr:
                if attr.type == BGP_ATTR_T['AS_PATH']:
                    for path_seg in attr.as_path:
                        if not path_seg['type'] == AS_PATH_SEG_T['AS_SEQUENCE']:
                            continue
                        yield (pref, strip_aspath([int(asn) for asn in path_seg['val']])[-1])


def genorigins(f, of):
    cache = {}

    d = Reader(f)

    for mm in d:
        m = mm.mrt
        if m.err == MRT_ERR_C['MRT Header Error']:
            prerror(m)
            continue

        if m.type == MRT_T['TABLE_DUMP_V2']:
            for (pfx, orig) in get_aspaths(m):
                if orig:
                    if not pfx in cache:
                        cache[pfx] = [orig]
                    else:
                        if not orig in cache[pfx]:
                            print("Duplicate origin for prefix %s: %s and %d" %(pfx, str(cache[pfx]), orig))
                            cache[pfx].append(orig)

    with open(of, 'w') as of:
        o = csv.writer(of, delimiter=',')
        o.writerow(['prefix', 'origin'])
        for k in cache:
            for orig in cache[k]:
                o.writerow((k, orig))


def main():
    genorigins(sys.argv[1], sys.argv[2])

if __name__ == '__main__':
    main()

