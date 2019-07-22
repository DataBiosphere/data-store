"""
JMESPath eventing and subscription admin tooling
"""
import typing
import argparse
import json
import logging

from cloud_blobstore import BlobNotFoundError

from dss.config import Replica
from dss.operations import dispatch
from dss.events.handlers.notify_v2 import build_bundle_metadata_document


logger = logging.getLogger(__name__)


events = dispatch.target("events", help=__doc__)


@events.action("bundle-metadata-document",
               arguments={"--replica": dict(choices=[r.name for r in Replica], required=True),
                          "--keys": dict(default=None,
                                         nargs="*",
                                         help="bundle keys to generate documents.")})
def bundle_metadata_document(argv: typing.List[str], args: argparse.Namespace):
    for key in args.keys:
        if not key.startswith("bundles/"):
            logger.warning(f"Unable to produce bundle metadata document for '{key}'")
            continue
        try:
            md = build_bundle_metadata_document(Replica[args.replica], key)
            print(json.dumps(md))
        except BlobNotFoundError:
            logger.error(f"Bundle not found for '{key}'")
