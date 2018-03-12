#!/bin/bash

URLBASE=(
"http://archive.routeviews.org/bgpdata/"
"http://archive.routeviews.org/route-views3/bgpdata/"
"http://archive.routeviews.org/route-views4/bgpdata/"
"http://archive.routeviews.org/route-views.eqix/bgpdata/"
"http://archive.routeviews.org/route-views.isc/bgpdata/"
"http://archive.routeviews.org/route-views.kixp/bgpdata/"
"http://archive.routeviews.org/route-views.jinx/bgpdata/"
"http://archive.routeviews.org/route-views.linx/bgpdata/"
"http://archive.routeviews.org/route-views.nwax/bgpdata/"
"http://archive.routeviews.org/route-views.telxatl/bgpdata/"
"http://archive.routeviews.org/route-views.wide/bgpdata/"
"http://archive.routeviews.org/route-views.sydney/bgpdata/"
"http://archive.routeviews.org/route-views.saopaulo/bgpdata/"
"http://archive.routeviews.org/route-views.sg/bgpdata/"
"http://archive.routeviews.org/route-views.perth/bgpdata/"
"http://archive.routeviews.org/route-views.sfmix/bgpdata/"
"http://archive.routeviews.org/route-views.soxrs/bgpdata/"
)

#MONTH="2017.05"
MONTH="2017.01"
TYPE="RIBS" # UPDATES or RIBS
#TIME="20170517.1000"
TIME="20170124.1000"

# http://archive.routeviews.org/bgpdata/2017.01/UPDATES/updates.20170109.1030.bz2

for b in ${URLBASE[*]}; do
	n="`echo $b | sed -r 's%http://[^/]+/([^/]+)/.*%\1%'`-${TYPE}-${MONTH}-${TIME}.bz2"
	type="rib"
	if [ $TYPE == "UPDATES" ]; then
	  type="updates"
	fi
	url="${b}${MONTH}/${TYPE}/${type}.${TIME}.bz2"

	echo "$url -> $n"
	wget -O $n $url
done

