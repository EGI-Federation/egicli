from __future__ import print_function

import os
import re
import xml.etree.ElementTree as ET

import click
from six.moves.urllib import parse
import requests
from tabulate import tabulate


GOCDB_PUBLICURL = "https://goc.egi.eu/gocdbpi/public/"


@click.group()
def endpoint():
    pass


@endpoint.command()
@click.option("--service-type", default='org.openstack.nova', help="Service type in GOCDB")
@click.option("--production/--not-producton", default=True, help="Production status")
@click.option("--monitored/--not-monitored", default=True, help="Monitoring status")
def list(service_type, production, monitored):
    q = {
        'method': 'get_service_endpoint',
        'service_type': service_type,
    }
    if monitored:
        q['monitored'] = 'Y'
    url = '?'.join([GOCDB_PUBLICURL, parse.urlencode(q)])
    # XXX UGLY, but GOC is using a IGTF CA not in standard distros
    r = requests.get(url, verify=False)
    endpoints = []
    if r.status_code == 200:
        root = ET.fromstring(r.text)
        for sp in root:
            if production:
                prod = sp.find('IN_PRODUCTION').text.upper()
                if prod != 'Y':
                    continue
            os_url = sp.find('URL').text
            #os_url = urlparse.urlparse(sp.find('URL').text)
            #sites[sp.find('SITENAME').text] = urlparse.urlunparse(
            #    (os_url[0], os_url[1], os_url[2], '', '', ''))
            endpoints.append([sp.find('SITENAME').text, service_type, os_url])
    else:
        print("Something went wrong...")
        print(r.status)
        print(r.text)
    print(tabulate(endpoints, headers=['Site', 'type', 'URL']))
