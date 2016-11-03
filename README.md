IPGates
===============

**IPGates** is a simple Python script to setup DNAT and SNAT using iptables. It allows e.g. non-root users to interact with netfilter in order to setup destination NAT and source NAT through a Linux gateway using iptables. It does so by providing a very limited interface to interact with iptables. All available services for destination NAT are stored in a configuration file. A cron job will automatically remove the new DNAT rules every evening around 6PM. All events are logged to /var/log/ipgates.log for accountability. 

## Usage

Choose the type of the NAT rule (`--dnat` for destination and `--snat` for source NAT) to be added or deleted (`-d`). Then choose one from the available services (`-s`) for DNAT or specify the internal (`-i`) and external (`-e`) IP addresses for source NAT. You can also just simply list all currently effective rules (`--list`).

### Options
```
$ python ipgates.py -h

                    It's not "Door to Heaven"... it is...
                   _____ _____   _____       _
                  |_   _|  __ \ / ____|     | |   v0.3.1
                    | | | |__) | |  __  __ _| |_ ___  ___
                    | | |  ___/| | |_ |/ _` | __/ _ \/ __|
                   _| |_| |    | |__| | (_| | ||  __/\__ \
                  |_____|_|     \_____|\__,_|\__\___||___/

usage: ipgates [-h] (--dnat | --snat | --list) [-i INTERNAL] [-e EXTERNAL]
               [-s {http,https,smb,sftp,dns}] [-d]

optional arguments:
  -h, --help            show this help message and exit
  --dnat                setup destination NAT
  --snat                setup source NAT
  --list                list all rules
  -i INTERNAL           internal IP address for source NAT
  -e EXTERNAL           external IP address for source NAT
  -s {http,https,smb,sftp,dns}
  -d                    remove rule

examples:
  - adding a destination NAT rule:
      $ python ipgates.py --dnat -s https
  - removing a destination NAT rule:
      $ python ipgates.py --dnat -s smb -d
  - adding a source NAT rule:
      $ python ipgates.py --snat -i 192.168.123.123 -e 123.123.123.123
  - removing a source NAT rule:
      $ python ipgates.py --snat -i 192.168.123.123 -e 123.123.123.123 -d
  - listing all rules:
      $ python ipgates.py --list
```

## License
This project is licensed under the terms of the MIT license.
