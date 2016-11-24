#!/usr/bin/env python

"""
IPGates is a simple Python script to setup DNAT and SNAT using iptables.

It allows e.g. non-root users to interact with netfilter in order to setup
destination NAT and source NAT through a Linux gateway using iptables. It does
so by providing a very limited interface to interact with iptables. All
available services for destination NAT are stored in a configuration file. A
cron job will automatically remove the new DNAT rules every evening around 6PM.
All events are logged to /var/log/ipgates.log for accountability. 
"""

__description__ = 'Setup destination NAT and source NAT using iptables'
__author__ = 'Gabor Seljan'
__version__ = '0.3.3'
__date__ = '2016/11/24'

import os
import sys
import iptc
import ipaddr
import logging
import textwrap
import subprocess
import configparser

from argparse import *
from random import randint
from crontab import CronTab
from cron_descriptor import get_description, ExpressionDescriptor

banner = ("""
                              It's not "Door to Heaven"... it is...
                             _____ _____   _____       _
                            |_   _|  __ \ / ____|     | |   v{}
                              | | | |__) | |  __  __ _| |_ ___  ___
                              | | |  ___/| | |_ |/ _` | __/ _ \/ __|
                             _| |_| |    | |__| | (_| | ||  __/\__ \\
                            |_____|_|     \_____|\__,_|\__\___||___/
""")

print(banner.format(__version__))

config = configparser.ConfigParser()
config.read('/opt/ipgates/ipgates.cfg')

parser = ArgumentParser(
    formatter_class=RawDescriptionHelpFormatter,
    description=__doc__,
    prog='ipgates',
    epilog=("""
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
"""),
)

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--dnat', action='store_true', default=False,
                   help='setup destination NAT')
group.add_argument('--snat', action='store_true', default=False,
                   help='setup source NAT')
group.add_argument('--list', action='store_true', default=False,
                   help='list all rules')

parser.add_argument('-i', dest='internal', default=False,
                    help='internal IP address for source NAT')
parser.add_argument('-e', dest='external', default=False,
                    help='external IP address for source NAT')
parser.add_argument('-s', dest='service', default=False,
                    choices=config.sections())
parser.add_argument('-d', dest='delete', action='store_true', default=False,
                    help='remove rule')

args = parser.parse_args()

if args.dnat and args.service:
    protocol = config[args.service]['protocol']
    shost = config[args.service]['shost']
    sport = config[args.service]['sport']
    dhost = config[args.service]['dhost']
    dport = config[args.service]['dport']

if os.environ.has_key('SUDO_USER'):
  USERNAME = os.environ['SUDO_USER']
else:
  USERNAME = os.environ['USER']

INSIDE = 'eth0'
OUTSIDE = 'eth1'

def is_valid_ip(ip):
    if ip:
        try:
            ipaddr.IPAddress(ip)
            return ip
        except ValueError as e:
            print('[!] {}'.format(e))
            logging.error(e)
            sys.exit(1)
    else:
        return False


def is_existing_rule(table, chain, target, in_interface=None, out_interface=None):
    t = iptc.Table(table)
    for c in t.chains:
        for r in c.rules:
            for m in r.matches:
                if (c.name == 'PREROUTING') and (chain == 'PREROUTING'):
                    if (r.protocol == protocol) and \
                       (r.dst == shost + '/255.255.255.255') and \
                       (m.dport == sport) and \
                       (r.target.name == target) and \
                       (r.target.to_destination == ':'.join([dhost, dport])):
                        msg = 'Rule in {} / {} already exists'.format(t.name.upper(), c.name)
                        print('[+] {}'.format(msg))
                        logging.info(msg, extra={'username': USERNAME})
                        msg = 'in: {} protocol: {} dst: {} dport: {} target: {} destination: {}'.format(
                            r.in_interface, r.protocol, r.dst, m.dport, r.target.name, r.target.to_destination)
                        print('\t{}'.format(msg).expandtabs(4))
                        logging.info(msg, extra={'username': USERNAME})
                        return True
                if (c.name == 'FORWARD') and (chain == 'FORWARD'):
                    if (r.protocol == protocol) and \
                       (r.in_interface == in_interface) and \
                       (r.out_interface == out_interface) and \
                       (r.dst == dhost + '/255.255.255.255') and \
                       (m.dport == dport) and \
                       (r.target.name == target):
                        msg = 'Rule in {} / {} already exists'.format(t.name.upper(), c.name)
                        print('[+] {}'.format(msg))
                        logging.info(msg, extra={'username': USERNAME})
                        msg = 'in: {} out: {} protocol: {} dst: {} dport: {} target: {}'.format(
                            r.in_interface, r.out_interface, r.protocol, r.dst, m.dport, r.target.name)
                        print('\t{}'.format(msg).expandtabs(4))
                        logging.info(msg, extra={'username': USERNAME})
                        return True
            if (c.name == 'POSTROUTING') and (chain == 'POSTROUTING'):
                if (r.in_interface == in_interface) and \
                   (r.out_interface == out_interface) and \
                   (r.src == args.internal + '/255.255.255.255') and \
                   (r.target.name == target) and \
                   (r.target.to_source == args.external):
                    msg = 'Rule in {} / {} already exists'.format(t.name.upper(), c.name)
                    print('[+] {}'.format(msg))
                    logging.info(msg, extra={'username': USERNAME})
                    msg = 'in: {} out: {} src: {} target: {} destination: {}'.format(
                        r.in_interface, r.out_interface, r.src, r.target.name, r.target.to_source)
                    print('\t{}'.format(msg).expandtabs(4))
                    logging.info(msg, extra={'username': USERNAME})
                    return True
    return False


def add_rule(table, chain, rule):
    msg = 'Adding rule to {} / {}'.format(table.name.upper(), chain.name)
    print('[+] {}'.format(msg))
    logging.info(msg, extra={'username': USERNAME})
    if chain.name == 'PREROUTING':
        # iptables -t nat -A PREROUTING -i eth1 -p tcp -d 123.123.123.123 --dport 22 -j DNAT --to-destination 192.168.123.123
        msg = 'in: {} protocol: {} dst: {} dport: {} target: {} destination: {}'.format(
            rule.in_interface, rule.protocol, rule.dst, rule.matches[0].dport, rule.target.name, rule.target.to_destination)
    elif chain.name == 'FORWARD':
        # iptables -A FORWARD -i eth1 -o eth0 -p tcp -d 192.168.123.123 --dport 22 -j ACCEPT
        msg = 'in: {} out: {} protocol: {} dst: {} dport: {} target: {}'.format(
            rule.in_interface, rule.out_interface, rule.protocol, rule.dst, rule.matches[0].dport, rule.target.name)
    elif chain.name == 'POSTROUTING':
        # iptables -t nat -A POSTROUTING -o eth1 -s 192.168.123.0/24 -j SNAT --to-source 123.123.123.123-123.123.123.133
        msg = 'in: {} out: {} src: {} target: {} destination: {}'.format(
            rule.in_interface, rule.out_interface, rule.src, rule.target.name, rule.target.to_source)
    print('\t{}'.format(msg).expandtabs(4))
    logging.info(msg, extra={'username': USERNAME})
    try:
        if chain.name == 'POSTROUTING':
            chain.insert_rule(rule)
        else:
            chain.append_rule(rule)
        table.commit()
        table.refresh()
    except iptc.IPTCError as e:
        print('[!] {}'.format(str(e).capitalize()))
        logging.error(e, extra={'username': USERNAME})


def delete_rule(table, chain, rule):
    msg = 'Deleting rule from {} / {}'.format(table.name.upper(), chain.name)
    print('[-] {}'.format(msg))
    logging.info(msg, extra={'username': USERNAME})
    if chain.name == 'PREROUTING':
        msg = 'in: {} protocol: {} dst: {} dport: {} target: {} destination: {}'.format(
            rule.in_interface, rule.protocol, rule.dst, rule.matches[0].dport, rule.target.name, rule.target.to_destination)
    elif chain.name == 'FORWARD':
        msg = 'in: {} out: {} protocol: {} dst: {} dport: {} target: {}'.format(
            rule.in_interface, rule.out_interface, rule.protocol, rule.dst, rule.matches[0].dport, rule.target.name)
    elif chain.name == 'POSTROUTING':
        msg = 'in: {} out: {} src: {} target: {} destination: {}'.format(
            rule.in_interface, rule.out_interface, rule.src, rule.target.name, rule.target.to_source)
    print('\t{}'.format(msg).expandtabs(4))
    logging.info(msg, extra={'username': USERNAME})
    try:
        chain.delete_rule(rule)
        table.commit()
        table.refresh()
    except iptc.IPTCError as e:
        print('[!] {}'.format(str(e).capitalize()))
        logging.error(e, extra={'username': USERNAME})


def is_existing_cronjob():
    cron = CronTab(tabfile='/etc/crontab', user=False)
    for job in cron.find_comment(args.service):
        return job.is_enabled()
    return False


def add_cronjob():
    if not is_existing_cronjob():
        cmd = 'ipgates --dnat -s {} -d'.format(args.service)
        msg = 'Adding cron job to automatically remove rule for {} service'.format(args.service.upper())
        print('[+] {}'.format(msg))
        logging.info(msg, extra={'username': USERNAME})
        cron = CronTab(tabfile='/etc/crontab', user=False)
        for job in cron.find_comment(args.service):
            job.enable()
            cron.write()
            msg = 'Execute "{}" {}'.format(cmd, job.description(use_24hour_time_format=True).lower())
            print('\t{}'.format(msg).expandtabs(4))
            logging.info(msg, extra={'username': USERNAME})
            return
        job = cron.new(command=cmd, comment=args.service, user='root')
        job.setall('{} 18 * * *'.format(randint(0, 59)))
        job.enable()
        cron.write()
        msg = 'Execute "{}" {}'.format(cmd, job.description(use_24hour_time_format=True).lower())
        print('\t{}'.format(msg).expandtabs(4))
        logging.info(msg, extra={'username': USERNAME})


def delete_cronjob():
    cron = CronTab(tabfile='/etc/crontab', user=False)
    for job in cron.find_comment(args.service):
        job.enable(False)
        cron.write()
        msg = 'Deleting cron job for {} service'.format(args.service.upper())
        print('[-] {}'.format(msg))
        logging.info(msg, extra={'username': USERNAME})
        return


def main():
    logging.basicConfig(
        filename='/var/log/ipgates.log',
        level=logging.INFO,
        format='%(asctime)s - %(username)s - %(levelname)s - %(message)s'
    )

    if args.dnat and args.service:
        table = iptc.Table('nat')
        table.autocommit = False
        chain = iptc.Chain(table, 'PREROUTING')
        rule = iptc.Rule()
        rule.in_interface = OUTSIDE
        rule.protocol = protocol
        rule.dst = shost
        match = rule.create_match(protocol)
        match.dport = sport
        target = rule.create_target('DNAT')
        target.to_destination = ':'.join([dhost, dport])

        if args.delete:
            delete_rule(table, chain, rule)
        elif not is_existing_rule('nat', 'PREROUTING', 'DNAT'):
            add_rule(table, chain, rule)

        table = iptc.Table('filter')
        table.autocommit = False
        chain = iptc.Chain(table, 'FORWARD')
        rule = iptc.Rule()
        rule.in_interface = OUTSIDE
        rule.out_interface = INSIDE
        rule.protocol = protocol
        rule.dst = dhost
        match = rule.create_match(protocol)
        match.dport = dport
        target = rule.create_target('ACCEPT')

        if args.delete:
            delete_rule(table, chain, rule)
            delete_cronjob()
        elif not is_existing_rule('filter', 'FORWARD', 'ACCEPT', OUTSIDE, INSIDE):
            add_rule(table, chain, rule)
            add_cronjob()

    if args.snat and is_valid_ip(args.internal) and is_valid_ip(args.external):
        table = iptc.Table('nat')
        table.autocommit = False
        chain = iptc.Chain(table, 'POSTROUTING')
        rule = iptc.Rule()
        rule.out_interface = OUTSIDE
        rule.src = args.internal
        target = rule.create_target('SNAT')
        target.to_source = args.external

        if args.delete:
            delete_rule(table, chain, rule)
        elif not is_existing_rule('nat', 'POSTROUTING', 'SNAT', INSIDE, OUTSIDE):
            add_rule(table, chain, rule)

    if args.list:
        print('[*] Listing rules in FILTER table...\n')
        subprocess.call(['iptables', '-nvL'])
        print('')
        print('[*] Listing rules in NAT table...\n')
        subprocess.call(['iptables', '-nvL', '-t', 'nat'])
        print('')
    elif args.service or args.dnat:
        if args.delete:
            print('[*] The gate is closed!')
        else:
            print('[*] Chevron seven is locked in place...the gate is open!')


if __name__ == '__main__':
    main()
