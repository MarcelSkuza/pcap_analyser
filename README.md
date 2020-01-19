# PCAP file analyser
Python program for network traffic analysis and visualisation. Extracts following information from packets:
- IP addresses 
- Emails
- URIs
- Pakcet type, count & mean lenght

## Libraries
**dpkt** - pcap parsing and decapsulation\
https://dpkt.readthedocs.io/en/latest/

**geoip2** - geolocation lookup for extracted IPs\
https://geoip2.readthedocs.io/en/latest/
\
https://dev.maxmind.com/geoip/geoip2/geolite2/ <- database

**simplekml** - kml file creation\
https://simplekml.readthedocs.io/en/latest/

**matplotlib** - traffic plot\
https://matplotlib.org/contents.html

**networkx** - network graph\
https://networkx.github.io/documentation/stable

## To do
1. Separate packet analysis into functions & support diffrent "modes" of parsing (if user doesn't want all features extracted)
