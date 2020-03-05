"""
Tools for managing FLAC dynamodb database
"""
import argparse
import logging
import typing
import os
import json

from dss import dynamodb as ddb
from dss.operations import dispatch
from dss.storage.identifiers import DSS_BUNDLE_KEY_REGEX, VERSION_REGEX, UUID_REGEX, FILE_PREFIX, TOMBSTONE_SUFFIX
logger = logging.getLogger(__name__)


class FlacHandler:
    def __init__(self, argv: typing.List[str], args: argparse.Namespace):
        self.keys = args.keys.copy()
        self.flac_lookup_table_name = f"dss-auth-lookup-${os.environ['DSS_DEPLOYMENT_STAGE']}"
        if args.groups:
            self.groups_to_use = args.groups.copy()

    @staticmethod
    def _parse_key(key):
        try:
            version = VERSION_REGEX.search(key).group(0)
            uuid = UUID_REGEX.search(key).group(0)
        except IndexError:
            raise RuntimeError(f'Unable to parse the key: {key}')
        return uuid, version

    def process_keys(self):
        raise NotImplementedError()

    def __call__(self, argv: typing.List[str], args: argparse.Namespace):
        self.process_keys()


checkout = dispatch.target("flac", help=__doc__)


@checkout.action("inspect",
                 arguments={"--keys": dict(nargs="+", help="Keys to inspect in DynamoDB", required=True)})
class Inspect(FlacHandler):
    def process_keys(self):
        key_status = []
        for _key in self.keys:
            uuid, version = self._parse_key(_key)
            temp_status = {"fqid": _key}
            try:
                flac_attributes = ddb.get_item(table=self.flac_lookup_table_name,hash_key=uuid)
            except ddb.DynamoDBItemNotFound:
                # nothing was found within the database
                pass
            else:
                temp_status.update(flac_attributes)
            key_status.append(temp_status)
        print(json.dumps(key_status, index=2))


@checkout.action("add",
                 arguments={"--keys": dict(nargs="+", help="Keys to inspect in DynamoDB", required=True)},
                           {"--groups": dict(nargs="+", help="Groups to attach to a object", required=True)})
class Add(FlacHandler):
    def process_keys(self):
        key_status = []
        update_expression = f"SET groups = :g"
        expression_attribute_values = {":g": {"SS": [{"S", group} for group in self.groups_to_use]}}
        for _key in self.keys:
            uuid, version = self._parse_key(_key)
            updated_attributes = ddb.update_item(table=self.flac_lookup_table_name, hash_key=uuid,
                                                 update_expression=update_expression,
                                                 expression_attribute_values=expression_attribute_values)
            key_status.append(updated_attributes)
        print(json.dumps(key_status, index=2))
