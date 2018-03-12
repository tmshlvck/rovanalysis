#!/usr/bin/python

addr = ['188.227.158.1', '188.227.159.1']

from ripe.atlas.cousteau import (
    Ping,
    Traceroute,
    AtlasSource,
    AtlasCreateRequest
    )

from datetime import datetime

ATLAS_API_KEY = "d3aa7fd8-87fa-403a-ab8f-681d8e433108"


def run_measurement(tgt):
    m = [Ping(af=4, target=addr, description="ROV tgt %d"%mid) for (mid, addr) in enumerate(tgt)]

    source = AtlasSource(type="area", value="WW", requested=1000)

    atlas_request = AtlasCreateRequest(
        start_time=datetime.utcnow(),
        key=ATLAS_API_KEY,
        measurements=m,
        sources=[source],
        is_oneoff=True
    )

    (is_success, response) = atlas_request.create()
    print "tgt=%s is_success=%s response=%s" % (str(tgt), str(is_success), str(response))



def main():
    run_measurement(addr)


if __name__ == '__main__':
    main()
