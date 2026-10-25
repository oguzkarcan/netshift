"""netshift - ARP-based "internet pause" demo tool for authorized labs.

The tool keeps a device associated with the Wi-Fi network but takes away its
internet access by answering ARP requests on the gateway's behalf.  It is meant
for classroom demos and home labs where every device on the network is yours.
"""

__version__ = "0.1.0"
