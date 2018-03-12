#!/bin/bash

URLBASE="http://data.ris.ripe.net/rrc"

#MONTH="2017.01"
MONTH="2017.05"
#TIME="20170124.0800"
TIME="20170517.1600"

# http://data.ris.ripe.net/rrc00/2017.06/bview.20170623.0800.gz 

for i in `seq 0 21`; do
	I=`printf "%02d\n" $i`
	n="rcc${I}-bview.${TIME}.gz"
	url="${URLBASE}${I}/${MONTH}/bview.${TIME}.gz"

	echo "$url -> $n"
	wget -O $n $url
done

