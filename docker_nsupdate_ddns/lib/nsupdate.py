import logging

import dns.update
import dns.query
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.tsigkeyring

config = {}

LOG = logging.getLogger(__name__)


def add_records(records):
    keyring = dns.tsigkeyring.from_text({config['TSIG_NAME']: config['TSIG_KEY']})

    for hostname, ip in records.items():
        delete_records({hostname:ip})
        LOG.info(f"Adding record for {hostname}({ip['IPv4'], ip['IPv6']})")

        for proto, addr in ip.items():
            if proto == 'IPv4':
                rrtype = dns.rdatatype.A
            if proto == 'IPv6':
                rrtype = dns.rdatatype.AAAA

            update = dns.update.Update(config['DOMAIN'], keyring=keyring)
            update.add(hostname, int(config['DNS_RECORD_TTL']), rrtype, addr)
            dns.query.tcp(update, config['NAMESERVER'], timeout=2, port=int(config['PORT']))

            if proto == 'IPv4' and 'REVERSE4_DOMAIN' in config:
                reventry = dns.reversename.from_address(addr)
                update = dns.update.Update(config['REVERSE4_DOMAIN'], keyring=keyring)
                update.add(reventry, int(config['DNS_RECORD_TTL']), dns.rdatatype.PTR, hostname + '.' + config['DOMAIN'] + '.')
                dns.query.tcp(update, config['NAMESERVER'], timeout=2, port=int(config['PORT']))

            if proto == 'IPv6' and 'REVERSE6_DOMAIN' in config:
                reventry = dns.reversename.from_address(addr)
                update = dns.update.Update(config['REVERSE6_DOMAIN'], keyring=keyring)
                update.add(reventry, int(config['DNS_RECORD_TTL']), dns.rdatatype.PTR, hostname + '.' + config['DOMAIN'] + '.')
                dns.query.tcp(update, config['NAMESERVER'], timeout=2, port=int(config['PORT']))


def delete_records(records):
    keyring = dns.tsigkeyring.from_text({config['TSIG_NAME']: config['TSIG_KEY']})

    for hostname, ip in records.items():
        if ip == None:
            LOG.info(f"Deleting record for {hostname}")
        else:
            LOG.info(f"Deleting record for {hostname}({ip['IPv4'], ip['IPv6']})")

        update = dns.update.Update(config['DOMAIN'], keyring=keyring)
        update.delete(hostname)
        dns.query.tcp(update, config['NAMESERVER'], timeout=2, port=int(config['PORT']))

        if ip != None:
            for proto, addr in ip.items():
                if proto == 'IPv4' and 'REVERSE4_DOMAIN' in config:
                    reventry = dns.reversename.from_address(addr)
                    update = dns.update.Update(config['REVERSE4_DOMAIN'], keyring=keyring)
                    update.delete(reventry)
                    dns.query.tcp(update, config['NAMESERVER'], timeout=2, port=int(config['PORT']))

                if proto == 'IPv6' and 'REVERSE6_DOMAIN' in config:
                    reventry = dns.reversename.from_address(addr)
                    update = dns.update.Update(config['REVERSE6_DOMAIN'], keyring=keyring)
                    update.delete(reventry)
                    dns.query.tcp(update, config['NAMESERVER'], timeout=2, port=int(config['PORT']))


def check_records(hostname, ip):
    ret = False
    for proto, addr in ip.items():
        if proto == 'IPv4':
            rrtype = dns.rdatatype.A
        if proto == 'IPv6':
            rrtype = dns.rdatatype.AAAA

        resolver = dns.resolver.Resolver()
        target_domain = hostname + '.' + config['DOMAIN'] + '.'
        try:
            answers = resolver.resolve(target_domain, rrtype)
            for rdata in answers:
                if str(rdata) == str(addr):
                    ret = True
        except dns.resolver.NoAnswer:
            LOG.error(f"No {proto} records found for {target_domain}")
        except dns.resolver.NXDOMAIN:
            LOG.error(f"Domain {target_domain} does not exist")
        except Exception as e:
            LOG.error(f"An error occurred: {e}")
    return ret


def init(_config):
    global config
    config = _config
