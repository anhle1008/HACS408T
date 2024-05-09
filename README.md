# HACS408T

## Project 2: Network Scanner

The implant is a comprehensive network scanning implant that provides several different scanning capabilities. The goal of this implant is to be able to drop it on a foreign network and explore in-depth the machines and attack surface available to the current user. The implant will have to discover both machines and open ports serving IPv4 with zero prior information about the network itself or the machines running on it. The implant manually constructs packets for host discovery with ARP. The code will generate a results.json file which contains network, machines within the network, and their open ports.
