# bcapi

Python implementation of the Breadcrumb API

Requirements:

- Ubuntu of some sort (probably any Linux)
- python-protobuf
- protobuf-compiler

Explanation:

These scripts are a very limited Python implementation of the Breadcrumb API, culminating in a script that generates "live stats" (dumped as a dictionary to a file) at a granularity of 8 seconds for all Breadcrumbs the script can find.

They were written largely to see if the BCAPI could be integrated using Python; they're not meant for production, but rather as a demonstration to software developers to then go ahead and make use of the concepts.

Usage:

python bc_livestats.py [source IP] [response IP] [trace IP] [role] [password]

source IP - the IP of the interface to multicast discovery packets from
response IP - the IP inside the discovery packets (the BCs will respond to this IP)
trace IP - the IP for each Breadcrumb to trace to to work out "next hop" (ideally this will be in the network core)
role - role to authenticate with (e.g. ADMIN)
password - password for that role (e.g. breadcrumb-admin for ADMIN role)

A file "breadcrumb_stats.txt" will be written to the folder the script was executed from, this will contain some nested dictionaries respresenting the status of the Breadcrumbs.

Issues:

Although it operates well on my dev environment, I've had issues using this in "production" (about 130 BCs); I believe this issues are mostly due to the platform it had to run on, which was a very old and sad Ubuntu 12.04 box that's running a bunch of different things. I get odd crashes and segmentation faults, with no real lead-up (e.g. memory over-use, CPU over-use).

I've not bothered digging too deeply into it, as it's really just to prove the concept. I think it's SSL library related though, either some GC I'm not doing properly in Python somewhere, or a deeper issue that is probably resolved in later versions of libssl.
