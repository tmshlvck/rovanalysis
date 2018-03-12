#!/usr/bin/python

targets = {'188.227.158.1', '188.227.159.1'}
indicators = {29134:29134, 378:378, 42000:29134, 5588:29134, 21320:378, 20965:378, 174:29134}

 
#msmids = [7830274, 7830275]
#msmids = [7892864, 7892865]
msmids = [8780089, 8780090]

msmreverted = [(8780067,8780068), (8780071,8780072), (8780073,8780074), (8780076,8780077), (8780080,8780081), (8780084,8780085), (8780086,8780087), (8780089,8780090)]

msmforward = [(7934009,7934010), (7934022,7934023), (7937437,7937438), (7942364,7942365), (7942381,7942382), (7942396,7942397), (7942403,7942404), (7942411,7942412), (7942417,7942418), (7942692,7942693), (7943542,7943543), (7943548,7943549)]


from datetime import datetime
from ripe.atlas.cousteau import AtlasResultsRequest
from ripe.atlas.sagan import Result
import iptree
import csv

asn_cache = None
def ask_asn(ip):
    global asn_cache

    if not asn_cache:
        asn_cache = iptree.IPLookupTree(ipv6=False)
        with open('../origins/origins.csv', 'r') as f:
            reader = csv.reader(f)
            next(reader)
            for r in reader:
                asn_cache.add(r[0], int(r[1]))

    if ip in asn_cache:
        return asn_cache.lookupBest(ip)

import itertools
def normalize_ip_path(ip_path):
    def most_common(L):
        groups = itertools.groupby(sorted(L))
        def _auxfun(inp):
            (item, iterable) = inp
            return len(list(iterable)), -L.index(item)
        return max(groups, key=_auxfun)[0]

    def get_one(hop):
        for h in hop:
            if h:
                return most_common([h for h in hop if h])
        return None

    def get_hop(hop):
        if len(hop) != 3:
            return None
        return get_one([ask_asn(ha) for ha in hop])

    #print("DEBUG ip_path=%s" % str(ip_path))

    if get_one(ip_path[-1]) in targets:
        return [get_hop(h) for h in ip_path[:-1]]
    else:
        return [get_hop(h) for h in ip_path]

def get_results(mid):
    kwargs = {
        "msm_id": mid,
        }

    is_success, results = AtlasResultsRequest(**kwargs).create()

    if is_success:
#        print(results)
        pass
    else:
        raise Exception("Unsuccessful when getting results.")

    ret = {}
    for r in results:
        rp = Result.get(r)

        #print("probe_id=%d probe_ip=%s path=%s" % (rp.probe_id, rp.origin, str(normalize_ip_path(rp.ip_path))))
        if rp.probe_id in ret:
            raise Exception("Probe ID %d is already in result." % rp.probe_id)
        else:
            ret[rp.probe_id] = normalize_ip_path(rp.ip_path)

    return ret


def get_direction(aspath):
    def get_last(asp):
        for asn in asp[::-1]:
            if asn:
                return asn
        return None

    last = get_last(aspath)
    if last in indicators:
        return indicators[last]
    else:
#        print("Unknown indicator: "+str(aspath))
        return last

def estimate_direction(aspath):
    d = get_direction(aspath)
#    if d == 29134:
#        print('Ignum')
#    elif d == 378:
#        print('Israel')
#    else:
#        print('Unknown %s' % str(d))
    return d

def compute_round(msmpair):
    rr1=get_results(msmpair[0])
    rr2=get_results(msmpair[1])

    r1={k: estimate_direction(rr1[k]) for k in rr1}
    r2={k: estimate_direction(rr2[k]) for k in rr2}

    probes = {}
    same = 0
    diff = 0
    incomplete = 0

    for k in set(r1.keys()) | set(r2.keys()):
        if k in r1 and k in r2 and r1[k] != None and r2[k] != None:
            if r1[k] == r2[k]:
                same += 1
                probes[k] = False
            else:
                #print("difference probe_id=%d r1=%s r2=%s" % (k, rr1[k], rr2[k]))
                diff += 1
                if not k in probes:
                    probes[k] = True
        else:
            incomplete += 1
            probes[k] = None

    print("pair %s same=%d diff=%d incomplete=%d" % (str(msmpair), same, diff, incomplete))
    return (probes, rr1, rr2)

def merge(common,new):
    for k in new:
        if new[k] == None or new[k] == False or (not k in common):
            common[k] = new[k]

def findrovasn(asp1, asp2):
    return set(asp1).symmetric_difference(set(asp2))

def main():
    import sys
    sys.stderr = None

    probesforward = {}
    rr1f = {}
    rr2f = {}

    for msmpair in msmforward:
        (prb, rr1, rr2) = compute_round(msmpair)
        merge(probesforward, prb)
        rr1f.update(rr1)
        rr2f.update(rr2)

    print("ROV affected probes:")
    print(str([pid for pid in probesforward if probesforward[pid] == True]))
    print('ROV count: %d' % sum([1 for pid  in probesforward if probesforward[pid] == True]))
    print('no-ROV count: %d' % sum([1 for pid  in probesforward if probesforward[pid] == False]))
    print('Incomplete count: %d' % sum([1 for pid  in probesforward if probesforward[pid] == None]))

    probesreverted = {}
    rr1r = {}
    rr2r = {}

    print("Working on reverted:")
    for msmpair in msmreverted:
        (prb, rr1, rr2) = compute_round(msmpair)
        merge(probesreverted, prb)
        rr1r.update(rr1)
        rr2r.update(rr2)

    print("ROV affected probes:")
    print(str([pid for pid in probesreverted if probesreverted[pid] == True]))
    print('ROV count: %d' % sum([1 for pid  in probesreverted if probesreverted[pid] == True]))
    print('no-ROV count: %d' % sum([1 for pid  in probesreverted if probesreverted[pid] == False]))
    print('Incomplete count: %d' % sum([1 for pid  in probesreverted if probesreverted[pid] == None]))

    totalrov = 0
    totalnorov = 0
    totalincomplete = 0
    rovasn = set()
    norovasn = set()
    print("Summary:")
    for k in set(probesforward.keys()) | set(probesreverted.keys()):
        if k in probesforward and k in probesreverted:
            if probesforward[k] == probesreverted[k]:
                if probesforward[k] == True:
                    rovasn |= set(rr1f[k] if k in rr1f else []) | set(rr2f[k] if k in rr2f else []) | set(rr1r[k] if k in rr1r else []) | set(rr2r[k] if k in rr2r else [])
                    totalrov+=1
                elif probesforward[k] == False:
                    totalnorov+=1
                    norovasn |= set(rr1f[k] if k in rr1f else []) | set(rr2f[k] if k in rr2f else []) | set(rr1r[k] if k in rr1r else []) | set(rr2r[k] if k in rr2r else [])
                else:
                    totalincomplete+=1
            else:
                totalincomplete+=1

    print("totals: rov=%d no-rov=%d incomplete=%d" % (totalrov, totalnorov, totalincomplete))
    print("ROV ASNs: %s (%d)" % (str(rovasn.difference(norovasn)), len(rovasn.difference(norovasn))))
    print("NOROV ASNs: (%d)" % len(norovasn))


if __name__ == '__main__':
    main()

