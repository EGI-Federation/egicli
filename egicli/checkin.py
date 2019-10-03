from __future__ import print_function

import os
import re

import click
from tabulate import tabulate
import requests

@click.group()
def token():
    pass

@token.command()
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
@click.option("--list-vos/--no-list-vos", default=False, help="List user VOs")
def refresh(
    checkin_client_id,
    checkin_client_secret,
    checkin_refresh_token,
    checkin_url,
    list_vos,
):
    """Mananages Check-in tokens"""
    # discover oidc refresh token endpoint
    r = requests.get(checkin_url + "/.well-known/openid-configuration")
    r.raise_for_status()
    token_ep = r.json()["token_endpoint"]
    userinfo_ep = r.json()["userinfo_endpoint"]
    refresh_data = {
        "client_id": checkin_client_id,
        "client_secret": checkin_client_secret,
        "grant_type": "refresh_token",
        "refresh_token": checkin_refresh_token,
        "scope": "openid email profile",
    }
    r = requests.post(
        token_ep, auth=(checkin_client_id, checkin_client_secret), data=refresh_data
    )
    r.raise_for_status()
    output = r.json()
    access_token = output['access_token']

    # shall we also to get the user info?
    if list_vos:
        r = requests.get(
            userinfo_ep,
            headers={"Authorization": "Bearer %s" % access_token},
        )
        r.raise_for_status()
        vos = []
        m = re.compile('urn:mace:egi.eu:group:(.*.):role=member#aai.egi.eu')
        for claim in r.json().get('eduperson_entitlement', []):
            vo = m.match(claim)
            if vo:
                vos.append(vo.groups()[0])
        output["VOs"] = '\n'.join(vos)
#'urn:mace:egi.eu:group:dih-voucher02.eosc-hub.eu:role=member#aai.egi.eu

 #       print(r.json())
    #print(output)
    print(tabulate([(k, v) for k,v in output.items()], headers=["Field", "Value"]))
