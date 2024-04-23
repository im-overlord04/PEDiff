#!/usr/bin/sh

pip install pefile
LOCATION=`pip show pefile |grep 'Location: ' | sed 's/.*Location: //'`
wget -O $LOCATION/pefile.py https://raw.githubusercontent.com/erocarrera/pefile/master/pefile.py