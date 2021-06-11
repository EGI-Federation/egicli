from __future__ import print_function

import os
import re

import click
from tabulate import tabulate
import requests


def oidc_discover(checkin_url):
    # discover oidc endpoints
    r = requests.get(checkin_url + "/.well-known/openid-configuration")
    r.raise_for_status()
    return r.json()


def token_refresh(
    checkin_client_id, checkin_client_secret, checkin_refresh_token, token_url
):
    """Mananages Check-in tokens"""
    refresh_data = {
        "client_id": checkin_client_id,
        "grant_type": "refresh_token",
        "refresh_token": checkin_refresh_token,
        "scope": "openid email profile eduperson_entitlement",
    }
    auth = None
    if checkin_client_secret:
        auth=(checkin_client_id, checkin_client_secret)
        refresh_data.update({"client_secret": checkin_client_secret})
    r = requests.post(token_url, auth=auth, data=refresh_data)
    r.raise_for_status()
    return r.json()


def refresh_access_token(
    checkin_client_id, checkin_client_secret, checkin_refresh_token, checkin_url
):
    oidc_ep = oidc_discover(checkin_url)
    return token_refresh(
        checkin_client_id,
        checkin_client_secret,
        checkin_refresh_token,
        oidc_ep["token_endpoint"],
    )["access_token"]


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
    required=False,
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
    oidc_ep = oidc_discover(checkin_url)
    output = token_refresh(
        checkin_client_id,
        checkin_client_secret,
        checkin_refresh_token,
        oidc_ep["token_endpoint"],
    )
    access_token = output["access_token"]
    # shall we also get the user info?
    if list_vos:
        r = requests.get(
            oidc_ep["userinfo_endpoint"],
            headers={"Authorization": "Bearer %s" % access_token},
        )
        r.raise_for_status()
        vos = []
        m = re.compile("urn:mace:egi.eu:group:(.*.):role=member#aai.egi.eu")
        for claim in r.json().get("eduperson_entitlement", []):
            vo = m.match(claim)
            if vo:
                vos.append(vo.groups()[0])
        output["VOs"] = "\n".join(vos)
    print(tabulate([(k, v) for k, v in output.items()], headers=["Field", "Value"]))
