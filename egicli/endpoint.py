from __future__ import print_function

import os
import time
import defusedxml.ElementTree as ET

import click
import jwt
from six.moves.urllib import parse
import requests
from tabulate import tabulate


from egicli.checkin import refresh_access_token

GOCDB_PUBLICURL = "https://goc.egi.eu/gocdbpi/public/"


EC3_REFRESHTOKEN_TEMPLATE = """
description refreshtoken (
    kind = 'component' and
    short = 'Tool to refresh LToS access token.' and
    content = 'Tool to refresh LToS access token.'
)
configure front (
@begin
  - vars:
      CLIENT_ID: %(client_id)s
      CLIENT_SECRET: %(client_secret)s
      REFRESH_TOKEN: %(refresh_token)s
    tasks:
    - name: Check if docker is available
      command: which docker
      changed_when: false
      failed_when: docker_installed.rc not in [0,1]
      register: docker_installed
    - name: local install of egicli
      block:
      - name: Create dir /usr/local/ec3/
        file: path=/usr/local/ec3/ state=directory
      - name: install git
        package:
          name: git
          state: present
      - name: upgrade pip
        pip:
          name:
          - git+http://github.com/enolfc/egicli@ec3
      - cron:
          name: "refresh token"
          minute: "*/5"
          job: "[ -f /usr/local/ec3/auth.dat ] && egicli endpoint ec3-refresh --checkin-client-id {{ CLIENT_ID }} --checkin-client-secret {{ CLIENT_SECRET }} --checkin-refresh-token {{ REFRESH_TOKEN }} --auth-file /usr/local/ec3/auth.dat &> /var/log/refresh.log"
          user: root
          cron_file: refresh_token
          state: present
      when: docker_installed.rc not in [ 0 ]
    - name: local install of egicli
      block:
      - cron:
          name: "refresh token"
          minute: "*/5"
          job: "[ -f /usr/local/ec3/auth.dat ] && docker run -v /usr/local/ec3/auth.dat:/usr/local/ec3/auth.dat egifedcloud/egicli egicli endpoint ec3-refresh --checkin-client-id {{ CLIENT_ID }} --checkin-client-secret {{ CLIENT_SECRET }} --checkin-refresh-token {{ REFRESH_TOKEN }} --auth-file /usr/local/ec3/auth.dat &> /var/log/refresh.log"
          user: root
          cron_file: refresh_token
          state: present
      when: docker_installed.rc not in [ 1 ]
@end
)
"""


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
    r = requests.post(url, json=body)
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
@click.option(
    "--site",
    help="Name of the site",
    default=lambda: os.environ.get("EGI_SITE", None),
)
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
    default=lambda: os.environ.get("OS_PROJECT_ID", None),
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
    "--auth-file",
    help="Authorization file",
    required=True,
    default="auth.dat",
)
def ec3_refresh(
    checkin_client_id,
    checkin_client_secret,
    checkin_refresh_token,
    checkin_url,
    auth_file,
):
    # Get the right endpoint from GOCDB
    access_token = refresh_access_token(
        checkin_client_id, checkin_client_secret, checkin_refresh_token, checkin_url
    )
    auth_file_contents = []
    with open(auth_file, "r") as f:
        for line in f.readlines():
            l = line.strip()
            if 'OpenStack' in l:
                auth_tokens = []
                for token in l.split(";"):
                    if token.strip().startswith("password"):
                        access_token = token.split("=")[1].strip()
                        if access_token[0] in ["'", '"']:
                            access_token = access_token[1:-1]
                        # FIXME(enolfc): add verification
                        payload = jwt.decode(access_token, verify=False)
                        now = int(time.time())
                        expires = int(payload['exp'])
                        if expires - now < 300:
                            access_token = refresh_access_token(
                                checkin_client_id,
                                checkin_client_secret,
                                checkin_refresh_token,
                                checkin_url
                            )
                        auth_tokens.append("password = %s" % access_token)
                    else:
                        auth_tokens.append(token.strip())
                auth_file_contents.append("; ".join(auth_tokens))
            elif l:
                auth_file_contents.append(l)
    with open(auth_file, "w+") as f:
        f.write("\n".join(auth_file_contents))


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
    default=lambda: os.environ.get("OS_PROJECT_ID", None),
)
@click.option(
    "--auth-file",
    help="Authorization file",
    required=True,
    default="auth.dat",
)
@click.option(
    "--template-dir",
    help="EC3 templates dir",
    required=True,
    default="./templates",
)
@click.option("--force", is_flag=True, help="Force rewrite of files")
def ec3(
    checkin_client_id,
    checkin_client_secret,
    checkin_refresh_token,
    checkin_url,
    site,
    project_id,
    auth_file,
    template_dir,
    force,
):
    if os.path.exists(auth_file) and not force:
        print("Auth file already exists, not replacing unless --force option is included")
        raise click.Abort()
    access_token = refresh_access_token(
        checkin_client_id, checkin_client_secret, checkin_refresh_token, checkin_url
    )
    # Get the right endpoint from GOCDB
    # assume first one is ok
    ep = find_endpoint("org.openstack.nova", site=site).pop()
    os_auth_url = ep[2]
    site_auth = [
        "id = %s" % site,
        "type = OpenStack",
        "username = egi.eu",
        "tenant = openid",
        "auth_version = 3.x_oidc_access_token",
        "host = %s" % os_auth_url,
        "domain = %s" % project_id,
        "password = '%s'" % access_token
    ]
    auth_file_contents = [";".join(site_auth)]
    if os.path.exists(auth_file):
        with open(auth_file, "r") as f:
            for line in f.readlines():
                if 'OpenStack' in line:
                    continue
                auth_file_contents.append(line)
    with open(auth_file, "w+") as f:
        f.write("\n".join(auth_file_contents))
    if not os.path.exists(template_dir):
        os.mkdir(template_dir)
    with open(os.path.join(template_dir, "refresh.radl"), "w+") as f:
        v = dict(client_id=checkin_client_id,
                 client_secret=checkin_client_secret,
                 refresh_token=checkin_refresh_token)
        f.write(EC3_REFRESHTOKEN_TEMPLATE % v)


@endpoint.command()
@click.option(
    "--service-type", default="org.openstack.nova", help="Service type in GOCDB"
)
@click.option("--production/--not-production", default=True, help="Production status")
@click.option("--monitored/--not-monitored", default=True, help="Monitoring status")
@click.option(
    "--site", help="Name of the site", default=lambda: os.environ.get("EGI_SITE", None)
)
def list(service_type, production, monitored, site):
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
    default=lambda: os.environ.get("OS_PROJECT_ID", None),
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
