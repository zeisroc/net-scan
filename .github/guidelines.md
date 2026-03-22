I would like to improve how the scans are done, and automatically find the HOSTNAME of each hosts.
By using the net-scan, i struggled in the following points:
1. I was not able to perform scans through proxychains as the nmap command was without `-sT`
2. Adding the hostname by end, which caused some errors...

Fixes to implement:
- Always do a `nmap -sT` scan (unless UDP is done)
- For most of the Windows machine, we can reach them via SMB which leaks the DOMAIN and the MACHINE name.
  - Do you have a reliable way to retieve those informations through SMB ? (golang, nmap, netexec ?)

Also perform review of the documentation, i guess there is some weird stuff. Make sure to be in line with the tools capabilities and output.

