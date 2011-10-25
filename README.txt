Small utility to grep for matching wireshark filter within many PCAP files.

Philippe Langlois
http://www.p1sec.com

--------------------------
Dependencies
--------------------------
sharktools        http://www.mit.edu/~armenb/sharktools/
python            (minimum python 2.4)

--------------------------
Usage
--------------------------
Whole frame contains the character "a" somewhere
./wiregrep.py 'frame contains "a"' ~/contrib/captures/*cap

An HTTP protocol contains GET somewhere
./wiregrep.py 'http and frame[100-199] contains "GET"' ~/contrib/captures/*cap

Some traffic is IP v6
./wiregrep.py 'ip.version eq 6' ~/contrib/captures/*cap

