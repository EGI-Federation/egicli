# EGI CLI: A command line for EGI Federation

`egicli` is a simple command line interface for interacting with some of the
services of EGI. It simplifies the discovery of endpoints and provides users
with the configuration for other 3rd party tools (e.g. OpenStack clients)

We are focusing on the EGI Cloud service, but other services may be supported
in the future

## Installation

### Python package

Just use pip (probably better on a virtualenv):

```
pip install egicli
```

Make sure that your environment has the EGI CAs properly installed and
configured for python:


If you don’t have the CA certificates installed in your machine, you can get
them from the [UMD EGI core Trust Anchor Distribution](http://repository.egi.eu/?category_name=cas)

Once installed, get the location of the requests CA bundle with:

```
python -m requests.certs
```

If the output of that command is `/etc/ssl/certs/ca-certificates.crt`, you can
add EGI CAs by executing:

```
cd /usr/local/share/ca-certificates
for f in /etc/grid-security/certificates/*.pem ; do ln -s $f $(basename $f .pem).crt; done
update-ca-certificates
```

If the output is `/etc/pki/tls/certs/ca-bundle.crt` add the EGI CAs with:

```
cd /etc/pki/ca-trust/source/anchors
ln -s /etc/grid-security/certificates/*.pem .
update-ca-trust extract
```

Otherwise, you are using internal requests bundle, which can be augmented with
the EGI CAs with:

```
cat /etc/grid-security/certificates/*.pem >> $(python -m requests.certs)
```

### Docker

You can use the `eglicli` container instead of installing it locally:

```
docker pull egifoundation/egicli
```

## Usage

The `egicli` has a `--help` option that should guide you through the different
options. Below you can find some more information about the commands.

Some options take their default values from environment variables if defined:

* `CHECKIN_CLIENT_ID` for `--checkin-client-id`
* `CHECKIN_CLIENT_SECRET` for `--checkin-client-secret`
* `CHECKIN_REFRESH_TOKEN` for `--checkin-refresh-token`
* `EGI_SITE` for `--site`

### token

```
egicli token refresh --help
Usage: egicli token refresh [OPTIONS]

Options:
  --checkin-client-id TEXT      Check-in client id  [required]
  --checkin-client-secret TEXT  Check-in client secret  [required]
  --checkin-refresh-token TEXT  Check-in client id  [required]
  --checkin-url TEXT            Check-in OIDC URL  [required]
  --list-vos / --no-list-vos    List user VOs
  --help                        Show this message and exit.
```

Gets a refreshed access token from Check-in. You can get the id, secret and
refresh token from the [Fedcloud Check-in client](https://aai.egi.eu/fedcloud/)

If `--list-vos` option is specified, the entitlements related to VOs will be
also displayed.

```
$ egicli token refresh
Field          Value
-------------  -----------------------------------------------------
access_token   eyJraWQiOiJvaWRjIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI...
token_type     Bearer
refresh_token  eyJhbGciOiJub25lIn0.eyJle5AiOjE2MDd4MTcxNTtsImp0....
expires_in     3599
scope          openid profile email
id_token       eyJraWQiOiJvaWRjIiwiYWxnIjoiUlMyNTYifQ.eyJ7dWIiO....
```

### endpoint list

Lists the endpoints in GOCDB matching a given service type.

```
$ egicli endpoint list --help
Usage: egicli endpoint list [OPTIONS]

Options:
  --service-type TEXT             Service type in GOCDB
  --production / --not-production  Production status
  --monitored / --not-monitored   Monitoring status
  --site TEXT                     Name of the site
  --help                          Show this message and exit.
```

List all OpenStack sites:

```
$ egicli endpoint list
Site                type                URL
------------------  ------------------  ------------------------------------------------
IFCA-LCG2           org.openstack.nova  https://api.cloud.ifca.es:5000/v3/
IN2P3-IRES          org.openstack.nova  https://sbgcloud.in2p3.fr:5000/v3
UA-BITP             org.openstack.nova  https://openstack.bitp.kiev.ua:5000/v3
RECAS-BARI          org.openstack.nova  https://cloud.recas.ba.infn.it:5000/v3
NCG-INGRID-PT       org.openstack.nova  https://nimbus.ncg.ingrid.pt:5000/v3
CLOUDIFIN           org.openstack.nova  https://cloud-ctrl.nipne.ro:443/v3
IISAS-GPUCloud      org.openstack.nova  https://keystone3.ui.savba.sk:5000/v3/
IISAS-FedCloud      org.openstack.nova  https://nova.ui.savba.sk:5000/v3/
UNIV-LILLE          org.openstack.nova  https://thor.univ-lille.fr:5000/v3
INFN-PADOVA-STACK   org.openstack.nova  https://egi-cloud.pd.infn.it:443/v3
CYFRONET-CLOUD      org.openstack.nova  https://api.cloud.cyfronet.pl:5000/v3/
SCAI                org.openstack.nova  https://fc.scai.fraunhofer.de:5000/v3
CESNET-MCC          org.openstack.nova  https://identity.cloud.muni.cz/v3
INFN-CATANIA-STACK  org.openstack.nova  https://stack-server.ct.infn.it:35357/v3
CESGA               org.openstack.nova  https://fedcloud-osservices.egi.cesga.es:5000/v3
100IT               org.openstack.nova  https://cloud-egi.100percentit.com:5000/v3/
```

List OCCI endpoints at CESGA:

```
$ egicli endpoint list --service-type 'eu.egi.cloud.vm-management.occi' --site CESGA
Site    type                             URL
------  -------------------------------  ----------------------------------------------------------------------
CESGA   eu.egi.cloud.vm-management.occi  https://fedcloud-services.egi.cesga.es:11443/?image=209&resource=small
```

### endpoint projects

List the projects accessible for a given endpoint

```
egicli endpoint projects --help
Usage: egicli endpoint projects [OPTIONS]

Options:
  --checkin-client-id TEXT      Check-in client id  [required]
  --checkin-client-secret TEXT  Check-in client secret  [required]
  --checkin-refresh-token TEXT  Check-in client id  [required]
  --checkin-url TEXT            Check-in OIDC URL  [required]
  --site TEXT                   Name of the site
  --help                        Show this message and exit.
```

List of projects for CESNET-MCC site:

```
$ egicli endpoint projects --site CESNET-MCC
id                                Name                  enabled    site
--------------------------------  --------------------  ---------  ----------
081396a827c94f3da0c922cf6d8fb7f7  vo.nextgeoss.eu       True       CESNET-MCC
0aa5b696969c42988b18beda3f85b885  dteam                 True       CESNET-MCC
10b972eed97940089b234f6257d7db72  demo.fedcloud.egi.eu  True       CESNET-MCC
24869cfe0e094f59a3110429e068eef2  vo.geoss.eu           True       CESNET-MCC
50fc58ed66a14106b40b9c6d7d9af86c  vo.max-centre.eu      True       CESNET-MCC
5bc62d60bbbc49d881bc0a948da710d6  vo.eurogeoss.eu       True       CESNET-MCC
d868dfd63a674d94bbd9d9b7b54443e3  panosc.eu             True       CESNET-MCC
eae2aa7f26334104906106bca4b82ae3  training.egi.eu       True       CESNET-MCC
```

### endpoint token

Gets a valid Keystone token for a given site and project.

```
$ egicli endpoint token --site CESNET-MCC --project-id 0aa5b696969c42988b18beda3f85b885
export OS_TOKEN="gAAAAABd5luMQudxBj8r5..."
```

### endpoint env

Gets the environmet for using a given site with OpenStack cli

```
$ egicli endpoint env --site CESNET-MCC --project-id 0aa5b696969c42988b18beda3f85b885
# environment for CESNET-MCC
export OS_AUTH_URL="https://identity.cloud.muni.cz/v3"
export OS_AUTH_TYPE="v3oidcaccesstoken"
export OS_IDENTITY_PROVIDER="egi.eu"
export OS_PROTOCOL="openid"
export OS_ACCESS_TOKEN="eyJraWQiOiJ..."
export OS_PROJECT_ID="0aa5b696969c42988b18beda3f85b885"
```
