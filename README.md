# netSnarf
netSnarf is a C program designed to sniff packets travelling on the wire, built with extensibility in mind.  Coupling has been consciously avoided to promote easy integration of new features, filters, rules, etc.  The hope is that anyone wanting to monitor network traffic, build a basic packet filter, or track network statistics can do so easily, by building off of netSnarf's core packet engine and following the module conventions found therein.  Happy sniffing!

# Currently implements
	-Basic header inspection (ETH, IP, TCP)
	-Logging, via mysql database
	-DNS lookups on ip addrs

# Future extensions
	-SSL/TLS decryption
	-Port to raspberry Pi

# Dependencies
    libpcap
    mysqlclient (only for database module)
    mysqlserver (only for database module)

# Install
netSnarf is built for and runs on Ubuntu Linux.  It should work with other Linux distros, although it has not been tested outside of Ubuntu.
To access the network interfaces, you must be either be root, or have root privelages and use 'sudo' (the build example uses 'sudo').  

To build and run netSnarf:<br />

    $ cd <netSnarf-directory>
    $ make [verbose]
    $ sudo ./snarfd [OPTION]

# Options
    -c    clear history records (requires database module) 

    -h    help, prints cli options

    -i <interface>    selects network interface to use for sniffing

    -s    show history records (requires database module)

# License
The MIT License (MIT)<br />
Copyright (c) 2015 Ian Van Houdt<br />
License details can be found in the 'netSnarf/' directory<br />
