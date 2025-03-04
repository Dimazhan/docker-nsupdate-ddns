import logging

import dns.update
import dns.query
import dns.tsigkeyring
import ipaddress

config = {}

LOG = logging.getLogger(__name__)


def add_records(records):
    keyring = dns.tsigkeyring.from_text({config['TSIG_NAME']: config['TSIG_KEY']})

    for hostname, ip in records.items():
        LOG.info(f"Adding record for {hostname}({ip['IPv4'], ip['IPv6']})")

        for proto, addr in ip.items():
            rrtype = "A"
            if proto == 'IPv4':
                rrtype = "A"
            if proto == 'IPv6':
                rrtype = "AAAA"

            update = dns.update.Update(config['DOMAIN'], keyring=keyring)
            update.add(hostname, int(config['DNS_RECORD_TTL']), rrtype, addr)
            dns.query.tcp(update, config['NAMESERVER'], timeout=2, port=int(config['PORT']))


def delete_records(records):
    keyring = dns.tsigkeyring.from_text({config['TSIG_NAME']: config['TSIG_KEY']})

    for hostname, ip in records.items():
        LOG.info(f"Deleting record for {hostname}({ip['IPv4'], ip['IPv6']})")

        update = dns.update.Update(config['DOMAIN'], keyring=keyring)
        update.delete(hostname)
        dns.query.tcp(update, config['NAMESERVER'], timeout=2, port=int(config['PORT']))


def init(_config):
    global config
    config = _config
