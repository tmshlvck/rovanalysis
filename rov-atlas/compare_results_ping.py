#!/usr/bin/python

#msmids = [7830274, 7830275]
msmids = [7830276, 7830277]

def get_results(mid):
    from datetime import datetime
    from ripe.atlas.cousteau import AtlasResultsRequest

    kwargs = {
        "msm_id": mid,
        }

    is_success, results = AtlasResultsRequest(**kwargs).create()

    if is_success:
#        print(results)
        pass
    else:
        raise Exception("Unsuccessful when getting results.")

    from ripe.atlas.sagan import Result
    ret = {}
    for r in results:
        rp = Result.get(r)
        print "probe_id=%d probe_ip=%s sent=%d recv=%d" % (rp.probe_id, rp.origin, rp.packets_sent, rp.packets_received)
        if rp.probe_id in ret:
            raise Exception("Probe ID %d is already in result." % rp.probe_id)
        else:
            ret[rp.probe_id] = False if rp.packets_sent > 0 and rp.packets_received == 0 else True

    return ret

def main():
    r1=get_results(msmids[0])
    r2=get_results(msmids[1])

    same12 = 0
    same21 = 0
    diff12 = 0
    diff21 = 0
    diffprobe12 = 0
    diffprobe21 = 0

    for k1 in r1.keys():
        if k1 in r2:
            if r1[k1] == r2[k1]:
                same12 += 1
            else:
                print "difference12 probe_id=%d" % k1
                diff12 += 1
        else:
            diffprobe12 += 1

    for k2 in r2.keys():
        if k2 in r1:
            if r1[k2] == r2[k2]:
                same21 += 1
            else:
                print "difference21 probe_id=%d" % k2
                diff21 += 1
        else:
            diffprobe21 += 1

    print "same12=%d same21=%d diff12=%d diff21=%d diffprobe12=%d diffprobe21=%d" % (same12, same21, diff12, diff21, diffprobe12, diffprobe21)

if __name__ == '__main__':
    main()

