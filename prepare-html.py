#! /usr/bin/python

import sys

#
# mv _sources source
# mv _static static
# find -name "*.html" -exec ./THIS-SCRIPT.py {} \;
#

fn = sys.argv[1]
lines = file(fn).readlines()
wf = file(fn, "w")
for line in lines:
	if "href" in line:
		line = line.replace("_static", "static")
		line = line.replace("_source", "source")
	wf.write(line)
wf.close()
