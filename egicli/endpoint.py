from __future__ import print_function

import os
import json
import xml.etree.ElementTree as ET

import click
from six.moves.urllib import parse
import requests
from tabulate import tabulate

from egicli.checkin import refresh_access_token

GOCDB_PUBLICURL = "https://goc.egi.eu/gocdbpi/public/"


def get_sites():
    q = {"method": "get_site_list", "certification_status": "Certified"}
    url = "?".join([GOCDB_PUBLICURL, parse.urlencode(q)])
    r = requests.get(url)
    sites = []
    if r.status_code == 200:
        root = ET.fromstring(r.text)
        for s in root:
            sites.append(s.attrib.get('NAME'))
    else:
        print("Something went wrong...")
        print(r.status)
        print(r.text)
    return sites


def find_endpoint(service_type, production=True, monitored=True, site=None):
    q = {"method": "get_service_endpoint", "service_type": service_type}
    if monitored:
        q["monitored"] = "Y"
    if site:
        q["sitename"] = site
        sites = [site]
    else:
        sites = get_sites()
    url = "?".join([GOCDB_PUBLICURL, parse.urlencode(q)])
    r = requests.get(url)
    endpoints = []
    if r.status_code == 200:
        root = ET.fromstring(r.text)
        for sp in root:
            if production:
                prod = sp.find("IN_PRODUCTION").text.upper()
                if prod != "Y":
                    continue
            os_url = sp.find("URL").text
            ep_site = sp.find('SITENAME').text
            if ep_site not in sites:
                continue
            # os_url = urlparse.urlparse(sp.find('URL').text)
            # sites[sp.find('SITENAME').text] = urlparse.urlunparse(
            #    (os_url[0], os_url[1], os_url[2], '', '', ''))
            endpoints.append([sp.find("SITENAME").text, service_type, os_url])
    else:
        print("Something went wrong...")
        print(r.status)
        print(r.text)
    return endpoints


def get_keystone_url(os_auth_url, path):
    url = parse.urlparse(os_auth_url)
    prefix = url.path.rstrip("/")
    if prefix.endswith("v2.0") or prefix.endswith("v3"):
        prefix = os.path.dirname(prefix)
    path = os.path.join(prefix, path)
    return parse.urlunparse((url[0], url[1], path, url[3], url[4], url[5]))


def get_unscoped_token(os_auth_url, access_token):
    """Get an unscopped token, trying various protocol names if needed"""
    protocols = ["openid", "oidc"]
    for p in protocols:
        try:
            unscoped_token = retrieve_unscoped_token(os_auth_url, access_token, p)
            return unscoped_token, p
        except RuntimeError:
            pass
    raise RuntimeError("Unable to get an scoped token")


def get_scoped_token(os_auth_url, access_token, project_id):
    unscoped_token, protocol = get_unscoped_token(os_auth_url, access_token)
    url = get_keystone_url(os_auth_url, "/v3/auth/tokens")
    body = {
        "auth": {
            "identity": {"methods": ["token"], "token": {"id": unscoped_token}},
            "scope": {"project": {"id": project_id}},
        }
    }
    r = requests.post(url, data=json.dumps(body))
    if r.status_code != requests.codes.created:
        raise RuntimeError("Unable to get an scoped token")
    else:
        return r.headers["X-Subject-Token"], protocol


def retrieve_unscoped_token(os_auth_url, access_token, protocol="openid"):
    """Request an unscopped token"""
    url = get_keystone_url(
        os_auth_url,
        "/v3/OS-FEDERATION/identity_providers/egi.eu/protocols/%s/auth" % protocol,
    )
    r = requests.post(url, headers={"Authorization": "Bearer %s" % access_token})
    if r.status_code != requests.codes.created:
        raise RuntimeError("Unable to get an unscoped token")
    else:
        return r.headers["X-Subject-Token"]


def get_projects(os_auth_url, unscoped_token):
    url = get_keystone_url(os_auth_url, "/v3/auth/projects")
    r = requests.get(url, headers={"X-Auth-Token": unscoped_token})
    r.raise_for_status()
    return r.json()["projects"]


@click.group()
def endpoint():
    pass


@endpoint.command()
@click.option(
    "--checkin-client-id",
    help="Check-in client id",
    required=True,
    default=lambda: os.environ.get("CHECKIN_CLIENT_ID", None),
)
@click.option(
    "--checkin-client-secret",
    help="Check-in client secret",
    required=True,
    default=lambda: os.environ.get("CHECKIN_CLIENT_SECRET", None),
)
@click.option(
    "--checkin-refresh-token",
    help="Check-in client id",
    required=True,
    default=lambda: os.environ.get("CHECKIN_REFRESH_TOKEN", None),
)
@click.option(
    "--checkin-url",
    help="Check-in OIDC URL",
    required=True,
    default=lambda: os.environ.get("CHECKIN_OIDC_URL", "https://aai.egi.eu/oidc"),
)
@click.option("--site", help="Name of the site")
def projects(
    checkin_client_id, checkin_client_secret, checkin_refresh_token, checkin_url, site
):
    # Get the right endpoint from GOCDB
    project_list = []
    access_token = refresh_access_token(
        checkin_client_id, checkin_client_secret, checkin_refresh_token, checkin_url
    )
    for ep in find_endpoint("org.openstack.nova", site=site):
        os_auth_url = ep[2]
        unscoped_token, _ = get_unscoped_token(os_auth_url, access_token)
        project_list.extend(
            [
                [p["id"], p["name"], p["enabled"], ep[0]]
                for p in get_projects(os_auth_url, unscoped_token)
            ]
        )
    print(tabulate(project_list, headers=["id", "Name", "enabled", "site"]))


@endpoint.command()
@click.option(
    "--checkin-client-id",
    help="Check-in client id",
    required=True,
    default=lambda: os.environ.get("CHECKIN_CLIENT_ID", None),
)
@click.option(
    "--checkin-client-secret",
    help="Check-in client secret",
    required=True,
    default=lambda: os.environ.get("CHECKIN_CLIENT_SECRET", None),
)
@click.option(
    "--checkin-refresh-token",
    help="Check-in client id",
    required=True,
    default=lambda: os.environ.get("CHECKIN_REFRESH_TOKEN", None),
)
@click.option(
    "--checkin-url",
    help="Check-in OIDC URL",
    required=True,
    default=lambda: os.environ.get("CHECKIN_OIDC_URL", "https://aai.egi.eu/oidc"),
)
@click.option(
    "--site", help="Name of the site", default=lambda: os.environ.get("EGI_SITE", None)
)
@click.option(
    "--project-id",
    help="Project ID",
    required=True,
    default=lambda: os.environ.get("OS_PORJECT_ID", None),
)
def token(
    checkin_client_id,
    checkin_client_secret,
    checkin_refresh_token,
    checkin_url,
    project_id,
    site,
):
    # Get the right endpoint from GOCDB
    access_token = refresh_access_token(
        checkin_client_id, checkin_client_secret, checkin_refresh_token, checkin_url
    )
    # assume first one is ok
    ep = find_endpoint("org.openstack.nova", site=site).pop()
    os_auth_url = ep[2]
    token, _ = get_scoped_token(os_auth_url, access_token, project_id)
    print('export OS_TOKEN="%s"' % token)


@endpoint.command()
@click.option(
    "--service-type", default="org.openstack.nova", help="Service type in GOCDB"
)
@click.option("--production/--not-producton", default=True, help="Production status")
@click.option("--monitored/--not-monitored", default=True, help="Monitoring status")
@click.option(
    "--site", help="Name of the site", default=lambda: os.environ.get("EGI_SITE", None)
)
def list(service_type, production, monitored, site):
    endpoints = find_endpoint(service_type, production, monitored, site)
    print(tabulate(endpoints, headers=["Site", "type", "URL"]))


@endpoint.command()
@click.option(
    "--service-type", default="org.openstack.nova", help="Service type in GOCDB"
)
@click.option("--production/--not-producton", default=True, help="Production status")
@click.option("--monitored/--not-monitored", default=True, help="Monitoring status")
@click.option(
    "--site", help="Name of the site", default=lambda: os.environ.get("EGI_SITE", None)
)
def show(service_type, production, monitored, site):
    endpoints = find_endpoint(service_type, production, monitored, site)
    print(tabulate(endpoints, headers=["Site", "type", "URL"]))


@endpoint.command()
@click.option(
    "--checkin-client-id",
    help="Check-in client id",
    required=True,
    default=lambda: os.environ.get("CHECKIN_CLIENT_ID", None),
)
@click.option(
    "--checkin-client-secret",
    help="Check-in client secret",
    required=True,
    default=lambda: os.environ.get("CHECKIN_CLIENT_SECRET", None),
)
@click.option(
    "--checkin-refresh-token",
    help="Check-in client id",
    required=True,
    default=lambda: os.environ.get("CHECKIN_REFRESH_TOKEN", None),
)
@click.option(
    "--checkin-url",
    help="Check-in OIDC URL",
    required=True,
    default=lambda: os.environ.get("CHECKIN_OIDC_URL", "https://aai.egi.eu/oidc"),
)
@click.option(
    "--site",
    help="Name of the site",
    required=True,
    default=lambda: os.environ.get("EGI_SITE", None),
)
@click.option(
    "--project-id",
    help="Project ID",
    required=True,
    default=lambda: os.environ.get("OS_PORJECT_ID", None),
)
def env(
    checkin_client_id,
    checkin_client_secret,
    checkin_refresh_token,
    checkin_url,
    project_id,
    site,
):
    # Get the right endpoint from GOCDB
    access_token = refresh_access_token(
        checkin_client_id, checkin_client_secret, checkin_refresh_token, checkin_url
    )
    # assume first one is ok
    ep = find_endpoint("org.openstack.nova", site=site).pop()
    os_auth_url = ep[2]
    token, protocol = get_scoped_token(os_auth_url, access_token, project_id)
    print("# environment for %s" % site)
    print('export OS_AUTH_URL="%s"' % os_auth_url)
    print('export OS_AUTH_TYPE="v3oidcaccesstoken"')
    print('export OS_IDENTITY_PROVIDER="egi.eu"')
    print('export OS_PROTOCOL="%s"' % protocol)
    print('export OS_ACCESS_TOKEN="%s"' % access_token)
    print('export OS_PROJECT_ID="%s"' % project_id)
