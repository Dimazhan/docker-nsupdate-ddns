import logging

import docker

config = {}

LOG = logging.getLogger(__name__)


def get_container_name(container):
    """
    Get name of container, try in the following order:
      - Check if hostname_label is set
      - Fall back to container Name
    """
    x = container.attrs['Name'][1:]

    if config['HOSTNAME_LABEL'] in container.attrs['Config']['Labels']:
        x = container.attrs['Config']['Labels'][config['HOSTNAME_LABEL']]

    x = x.replace("_", "-")  # Be compliant with RFC1035
    return x


def get_container_ip(container):
    """
    Get IP of container. Try in the following order
     - default_network
     - First found network
     - Fall back to ['NetworkSettings']['IPAddress']
    """
    x = {}

    x['IPv4'] = container.attrs['NetworkSettings']['IPAddress']
    x['IPv6'] = container.attrs['NetworkSettings']['GlobalIPv6Address']

    if next(iter(container.attrs['NetworkSettings']['Networks'])):
        network_name = next(
            iter(container.attrs['NetworkSettings']['Networks']))
        x['IPv4'] = container.attrs['NetworkSettings']['Networks'][network_name]['IPAddress']
        x['IPv6'] = container.attrs['NetworkSettings']['Networks'][network_name]['GlobalIPv6Address']

    if config['DEFAULT_NETWORK'] in container.attrs['NetworkSettings']['Networks']:
        x['IPv4'] = container.attrs['NetworkSettings']['Networks'][config['DEFAULT_NETWORK']]['IPAddress']
        x['IPv6'] = container.attrs['NetworkSettings']['Networks'][config['DEFAULT_NETWORK']]['GlobalIPv6Address']

    return x


def generate_container_list():
    client = docker.from_env()

    container_list = client.containers.list()
    ipam = {}

    for container in container_list:
        if config['IGNORE_LABEL'] in container.attrs['Config']['Labels']:
            LOG.debug(f"Ignoring container {container.attrs['Name']} as ignore label present")
            continue

        container_name = get_container_name(container)
        container_ip = get_container_ip(container)
        if container_ip:
            ipam[container_name] = container_ip

    return ipam


def init(_config):
    global config
    config = _config
