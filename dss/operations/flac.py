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
from dss.storage.identifiers import VERSION_REGEX, UUID_REGEX
logger = logging.getLogger(__name__)


class FlacHandler:
    def __init__(self, argv: typing.List[str], args: argparse.Namespace):
        self.keys = args.keys.copy()
        self.flac_lookup_table_name = f"dss-auth-lookup-{os.environ['DSS_DEPLOYMENT_STAGE']}"

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
        # TODO: ideally this would be a threaded operation to handle many keys
        self.process_keys()


flac = dispatch.target("flac", help=__doc__)


@flac.action("get",
             arguments={"--keys": dict(nargs="+", help="Keys to inspect in DynamoDB", required=True)})
class Get(FlacHandler):
    def process_keys(self):
        key_status = []
        for _key in self.keys:
            uuid, version = self._parse_key(_key)
            temp_status = {"key": _key}
            try:
                flac_attributes = ddb.get_item(table=self.flac_lookup_table_name, hash_key=uuid)
            except ddb.DynamoDBItemNotFound:
                temp_status['inDatabase'] = False
                # nothing was found within the database
                pass
            else:
                temp_status.update(flac_attributes)
                temp_status['inDatabase'] = True
            key_status.append(temp_status)
        print(json.dumps(key_status, indent=2))
        return key_status  # action_handler does not really use this, its just testing


@flac.action("add",
             arguments={"--keys": dict(nargs="+", help="Keys to inspect in DynamoDB", required=True),
                        "--groups": dict(nargs="+", help="Groups to attach to a object", required=True)})
class Add(FlacHandler):
    def __init__(self, argv: typing.List[str], args: argparse.Namespace):
        super().__init__(argv, args)
        self.groups_to_use = list(set(args.groups.copy()))

    def process_keys(self):
        key_status = []
        update_expression = f"SET groups = :g"
        expression_attribute_values = {":g": {"L": [{"S": group} for group in self.groups_to_use]}}
        for _key in self.keys:
            uuid, version = self._parse_key(_key)
            updated_attributes = ddb.update_item(table=self.flac_lookup_table_name, hash_key=uuid,
                                                 update_expression=update_expression,
                                                 expression_attribute_values=expression_attribute_values)
            updated_attributes['key'] = _key
            key_status.append(updated_attributes)
        print(json.dumps(key_status, indent=2))
        return key_status  # action_handler does not really use this, its just testing


@flac.action("remove",
             arguments={"--keys": dict(nargs="+", help="Keys to inspect in DynamoDB", required=True)})
class Remove(FlacHandler):
    def process_keys(self):
        for _key in self.keys:
            uuid, version = self._parse_key(_key)
            ddb.delete_item(table=self.flac_lookup_table_name, hash_key=uuid)
