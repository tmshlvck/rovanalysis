#!/usr/bin/env python3

import sys
#from datetime import *
from mrtparse import *
import csv
import multiprocessing



lookforpref = ['188.227.158.0/24','188.227.159.0/24']




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


def get_aspaths(m):
    if ( m.subtype == TD_V2_ST['RIB_IPV4_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV4_MULTICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_MULTICAST']):

        pref = "%s/%d" % (m.rib.prefix, m.rib.plen)
        if not pref in lookforpref: # Not interested in the prefix
            return

        for entry in m.rib.entry:
            src = entry.peer_index
            for attr in entry.attr:
                if attr.type == BGP_ATTR_T['AS_PATH']:
                    path = []
                    for path_seg in attr.as_path:
                        if not path_seg['type'] == AS_PATH_SEG_T['AS_SEQUENCE']:
                            continue
                        path.extend(path_seg['val'])
            yield (pref,src,str(path))

def processfile(f):
    with open(f+".csv", 'w') as of:
        o = csv.writer(of, delimiter=',')
        o.writerow(['prefix', 'src_peer', 'aspath'])
        d = Reader(f)

        for mm in d:
            m = mm.mrt
            if m.err == MRT_ERR_C['MRT Header Error']:
                prerror(m)
                continue

            if m.type == MRT_T['TABLE_DUMP_V2']:
                for res in get_aspaths(m):
                    if res:
                        o.writerow(res)


def main():

    pool = multiprocessing.Pool(processes=10)
    pool.apply(processfile, sys.argv[1:])

if __name__ == '__main__':
    main()

