import logging

import click

@click.group()
@click.option('--debug/--no-debug', default=False)
def cli(debug):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level)

from egi_cli.checkin import token
cli.add_command(token)
from egi_cli.endpoint import endpoint
cli.add_command(endpoint)

if __name__ == "__main__":
    cli()
