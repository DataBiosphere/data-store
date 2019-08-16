"""
Get/set secret variable values from the AWS Secrets Manager
"""
import os
import sys
import select
import typing
import argparse
import json
import logging

from botocore.exceptions import ClientError

from dss.operations import dispatch
from dss.util.aws.clients import secretsmanager  # type: ignore

logger = logging.getLogger(__name__)


def get_secretsmanager_prefix(args):
    """
    Use information from the environment to assemble
    the necessary prefix for accessing variables in
    the SecretsManager.
    """
    store_name = os.environ["DSS_SECRETS_STORE"]
    stage_name = os.environ["DSS_DEPLOYMENT_STAGE"]
    store_prefix = f"{store_name}/{stage_name}/"
    return store_prefix


events = dispatch.target("secrets", arguments={}, help=__doc__)


@events.action(
    "list",
    arguments={
        "--json": dict(
            default=False,
            action="store_true",
            help="format the output as JSON if this flag is present",
        )
    },
)
def list_secrets(argv: typing.List[str], args: argparse.Namespace):
    """
    Print a list of names of every secret variable in the secrets manager
    for the given store and stage.
    """
    store_prefix = get_secretsmanager_prefix(args)

    paginator = secretsmanager.get_paginator("list_secrets")

    secret_names = []
    for response in paginator.paginate():
        for secret in response["SecretList"]:

            # Get resource IDs
            secret_name = secret["Name"]

            # Only save secrets for this store and stage
            if secret_name.startswith(store_prefix):
                secret_names.append(secret_name)

    secret_names.sort()

    if args.json is True:
        print(json.dumps(secret_names, indent=4))
    else:
        for secret_name in secret_names:
            print(secret_name)


@events.action(
    "get",
    arguments={
        "--secret-names": dict(
            required=True,
            nargs="*",
            help="names of secrets to retrieve (separate multiple values with spaces)",
        ),
        "--json": dict(
            default=False,
            action="store_true",
            help="format the output as JSON if this flag is present",
        ),
    },
)
def get_secret(argv: typing.List[str], args: argparse.Namespace):
    """
    Get the value of the secret variable (or list of variables) specified by
    the --secret-names flag; separate multiple secret names using a space.
    """
    # Note: this function should not print anything except the final JSON,
    # in case the user pipes the JSON output of this script to something else

    store_prefix = get_secretsmanager_prefix(args)

    # Make sure something was specified for secret name(s)
    if len(args.secret_names) == 0:
        raise RuntimeError(
            "Unable to set secret: no secret name was specified! Use the --secret-names flag."
        )
    else:
        secret_names = args.secret_names

    # Tack on the store prefix if it isn't there already
    for i in range(len(secret_names)):
        secret_name = secret_names[i]
        if not secret_name.startswith(store_prefix):
            secret_names[i] = store_prefix + secret_name

    # Determine if we should format output as JSON
    use_json = False
    if args.json is True:
        use_json = True

    for secret_name in secret_names:
        # Attempt to obtain secret
        try:
            response = secretsmanager.get_secret_value(SecretId=secret_name)
            secret_val = response["SecretString"]
        except ClientError:
            # A secret variable with that name does not exist
            logger.warning(f"Resource not found: {secret_name}")
        else:
            # Get operation was successful, secret variable exists
            if use_json:
                # Sometimes secret_val can be a dictionary
                try:
                    secret_val = json.loads(secret_val)
                except json.decoder.JSONDecodeError:
                    pass
                print(json.dumps({secret_name: secret_val}, indent=4))
            else:
                print(f"{secret_name}={secret_val}")


@events.action(
    "set",
    arguments={
        "--secret-name": dict(
            required=True, help="name of secret to set (limit 1 at a time)"
        ),
        "--secret-value": dict(
            required=False,
            default=None,
            help="value of secret to set (optional, if not present then stdin will be used)",
        ),
        "--dry-run": dict(
            default=False,
            action="store_true",
            help="do a dry run of the actual operation",
        ),
    },
)
def set_secret(argv: typing.List[str], args: argparse.Namespace):
    """Set the value of the secret variable specified by the --secret-name flag"""
    store_prefix = get_secretsmanager_prefix(args)

    # Make sure a secret name was specified
    if len(args.secret_name) == 0:
        raise RuntimeError(
            "Unable to set secret: no secret name was specified! Use the --secret-name flag."
        )
    secret_name = args.secret_name

    # Tack on the store prefix if it isn't there already
    if not secret_name.startswith(store_prefix):
        secret_name = store_prefix + secret_name

    # Decide what to use for input
    if args.secret_value is not None:
        secret_val = args.secret_value
    else:
        # Use stdin (input piped to this script) as secret value.
        # stdin provides secret value, flag --secret-name provides secret name.
        if not select.select([sys.stdin], [], [])[0]:
            err_msg = f"No data in stdin, cannot set secret {secret_name} without "
            err_msg += "a value from stdin or without --secret-value flag!"
            raise RuntimeError(err_msg)
        secret_val = sys.stdin.read()

    # Create or update
    try:
        # Start by trying to get the secret variable
        secretsmanager.get_secret_value(SecretId=secret_name)

    except ClientError:
        # A secret variable with that name does not exist, so create it

        if args.dry_run:
            # Create it for fakes
            print(
                f"Secret variable {secret_name} not found in secrets manager, dry-run creating it"
            )
        else:
            # Create it for real
            print(
                f"Secret variable {secret_name} not found in secrets manager, creating it"
            )
            secretsmanager.create_secret(Name=secret_name, SecretString=secret_val)

    else:
        # Get operation was successful, secret variable exists
        if args.dry_run:
            # Update it for fakes
            print(
                f"Secret variable {secret_name} found in secrets manager, dry-run updating it"
            )
        else:
            # Update it for real
            print(
                f"Secret variable {secret_name} found in secrets manager, updating it"
            )
            secretsmanager.update_secret(SecretId=secret_name, SecretString=secret_val)


@events.action(
    "delete",
    arguments={
        "--secret-name": dict(
            required=True, help="name of secret to delete (limit 1 at a time)"
        ),
        "--force": dict(
            default=False,
            action="store_true",
            help="force the delete operation to happen non-interactively (no user prompt)",
        ),
        "--dry-run": dict(
            default=False,
            action="store_true",
            help="do a dry run of the actual operation",
        ),
    },
)
def del_secret(argv: typing.List[str], args: argparse.Namespace):
    """
    Delete the value of the secret variable specified by the
    --secret-name flag from the secrets manager
    """
    store_prefix = get_secretsmanager_prefix(args)

    # Make sure a secret name was specified
    if len(args.secret_name) == 0:
        raise RuntimeError(
            "Unable to set secret: no secret name was specified! Use the --secret-name flag."
        )
    secret_name = args.secret_name

    # Tack on the store prefix if it isn't there already
    if not secret_name.startswith(store_prefix):
        secret_name = store_prefix + secret_name

    if args.force is False:
        # Make sure the user really wants to do this
        confirm = f"""
        Are you really sure you want to delete secret {secret_name}? (Type 'y' or 'yes' to confirm):
        """
        response = input(confirm)
        if response.lower() not in ["y", "yes"]:
            raise RuntimeError("You safely aborted the delete secret operation!")

    try:
        # Start by trying to get the secret variable
        secretsmanager.get_secret_value(SecretId=secret_name)

    except ClientError:
        # No secret var found
        logger.warning(f"Secret variable {secret_name} not found in secrets manager!")

    except secretsmanager.exceptions.InvalidRequestException:
        # Already deleted secret var
        logger.warning(
            f"Secret variable {secret_name} already marked for deletion in secrets manager!"
        )

    else:
        # Get operation was successful, secret variable exists
        if args.dry_run:
            # Delete it for fakes
            print(
                f"Secret variable {secret_name} found in secrets manager, dry-run deleting it"
            )
        else:
            # Delete it for real
            print(
                f"Secret variable {secret_name} found in secrets manager, deleting it"
            )
            secretsmanager.delete_secret(SecretId=secret_name)
