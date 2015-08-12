# netSnarf
C program to sniff packets travelling on the wire, built with extensibility in mind

Currently implements:
	-Basic header inspection (ETH, IP, TCP)
	-Logging, via mysql database
	-DNS lookups on ip addrs

Future extensions:
	-SSL/TLS decryption
	-Port to raspberry Pi

# Dependencies
libpcap
mysqlclient (only for database module)
mysqlserver (only for database module)

# License
The MIT License (MIT)
Copyright (c) 2015 Ian Van Houdt
