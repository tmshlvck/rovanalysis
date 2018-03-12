#!/usr/bin/env python

import sys
from optparse import OptionParser
from datetime import *
from mrtparse import *
from multiprocessing import Pool




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


def get_paths(m):
    result = []
    if ( m.subtype == TD_V2_ST['RIB_IPV4_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV4_MULTICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_UNICAST']
        or m.subtype == TD_V2_ST['RIB_IPV6_MULTICAST']):

        pref = "%s/%d" % (m.rib.prefix, m.rib.plen)
        if not pref in lookforpref: # Not interested in the prefix
            return []

        for entry in m.rib.entry:
            for attr in entry.attr:
                if attr.type == BGP_ATTR_T['AS_PATH']:
		    path = []
                    for path_seg in attr.as_path:
                        if not path_seg['type'] == AS_PATH_SEG_T['AS_SEQUENCE']:
                            continue
                        path.append(path_seg['val'])
		    result.append(path)
    return (pref,result)



def analyze(paths):
    pfx1,pfx2 = lookforpref

    status = {}

    if (not pfx1 in paths) or (not pfx2 in paths):
        raise Exception("Prefix %s present=%s, prefix %s present=%s" % (pfx1, str(pfx1 in paths), pfx2, str(pfx2 in paths)))

    for p in paths[pfx1]:
        if p in paths[pfx2]:
            status[p] = 3
	else:
            status[p] = 1

    for p in paths[pfx2]:
        if p in paths[pfx1]:
            status[p] = 3
        else:
            status[p] = 2

    print "Prefix %s has and prefix %s does not have:" % (pfx1, pfx2)
    for k in status.keys():
	if status[k] == 1:
	    print str(k)

    print "Prefix %s has and prefix %s does not have:" % (pfx2, pfx1)
    for k in status.keys():
	if status[k] == 2:
	    print str(k)

    return status

def main():
    def lsf(lst):
	return ([] if lst == None else lst)

    def merge(d1, d2):
	return {k: list(set(lsf(d1[k]) + lsf(d2[k]))) for k in list(set(lsf(d1.keys())+lsf(d2.keys())))}

    def pool_run(m):
        d = Reader(f)
	result = {}

        for m in d:
            m = m.mrt
            if m.err == MRT_ERR_C['MRT Header Error']:
                prerror(m)
                continue

            if m.type == MRT_T['TABLE_DUMP_V2']:
                result = merge(result, get_paths(m))

	return result

    pool = Pool(processes=10)
    vp_paths = pool.map(pool_run, sys.argv[1:])
    results = {}
    for r in vp_paths:
        results = merge(results, r)
        s = analyze(r)


if __name__ == '__main__':
    main()

