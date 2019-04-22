import io
from functools import lru_cache
import json
import typing
import time

import cachetools
from cloud_blobstore import BlobNotFoundError, BlobStore
from cloud_blobstore.s3 import S3BlobStore

from dss import Config, Replica
from dss.storage.identifiers import DSS_BUNDLE_KEY_REGEX, DSS_BUNDLE_TOMBSTONE_REGEX, BundleTombstoneID, BundleFQID
from dss.storage.blobstore import test_object_exists, idempotent_save
from dss.util import multipart_parallel_upload


_cache_key_template = "{replica}{fqid}"
_bundle_manifest_cache = cachetools.LRUCache(maxsize=4)


def get_bundle_manifest(
        uuid: str,
        replica: Replica,
        version: typing.Optional[str],
        *,
        bucket: typing.Optional[str] = None) -> typing.Optional[dict]:
    cache_key = _cache_key_template.format(replica=replica.name, fqid=BundleFQID(uuid, version).to_key())
    if cache_key in _bundle_manifest_cache:
        return _bundle_manifest_cache[cache_key]
    else:
        bundle = _get_bundle_manifest(uuid, replica, version, bucket=bucket)
        if bundle is not None:
            _bundle_manifest_cache[cache_key] = bundle
        return bundle


def _get_bundle_manifest(
        uuid: str,
        replica: Replica,
        version: typing.Optional[str],
        *,
        bucket: typing.Optional[str] = None) -> typing.Optional[dict]:
    """
    Return the contents of the bundle manifest file from cloud storage, subject to the rules of tombstoning.  If version
    is None, return the latest version, once again, subject to the rules of tombstoning.

    If the bundle cannot be found, return None
    """
    uuid = uuid.lower()

    handle = Config.get_blobstore_handle(replica)
    default_bucket = replica.bucket

    # need the ability to use fixture bucket for testing
    bucket = default_bucket if bucket is None else bucket

    def tombstone_exists(uuid: str, version: typing.Optional[str]):
        return test_object_exists(handle, bucket, BundleTombstoneID(uuid=uuid, version=version).to_key())

    # handle the following deletion cases
    # 1. the whole bundle is deleted
    # 2. the specific version of the bundle is deleted
    if tombstone_exists(uuid, None) or (version and tombstone_exists(uuid, version)):
        return None

    # handle the following deletion case
    # 3. no version is specified, we want the latest _non-deleted_ version
    if version is None:
        # list the files and find the one that is the most recent.
        prefix = f"bundles/{uuid}."
        object_names = handle.list(bucket, prefix)
        version = _latest_version_from_object_names(object_names)

    if version is None:
        # no matches!
        return None

    bundle_fqid = BundleFQID(uuid=uuid, version=version)

    # retrieve the bundle metadata.
    try:
        bundle_manifest_blob = handle.get(bucket, bundle_fqid.to_key()).decode("utf-8")
        return json.loads(bundle_manifest_blob)
    except BlobNotFoundError:
        return None


def save_bundle_manifest(replica: Replica, uuid: str, version: str, bundle: dict) -> typing.Tuple[bool, bool]:
    handle = Config.get_blobstore_handle(replica)
    data = json.dumps(bundle).encode("utf-8")
    fqid = BundleFQID(uuid, version).to_key()
    created, idempotent = idempotent_save(handle, replica.bucket, fqid, data)
    if created and idempotent:
        cache_key = _cache_key_template.format(replica=replica.name, fqid=fqid)
        _bundle_manifest_cache[cache_key] = bundle
    return created, idempotent


def _latest_version_from_object_names(object_names: typing.Iterator[str]) -> str:
    dead_versions = set()  # type: typing.Set[str]
    all_versions = set()  # type: typing.Set[str]
    set_checks = [
        (DSS_BUNDLE_TOMBSTONE_REGEX, dead_versions),
        (DSS_BUNDLE_KEY_REGEX, all_versions),
    ]

    for object_name in object_names:
        for regex, version_set in set_checks:
            match = regex.match(object_name)
            if match:
                _, version = match.groups()
                version_set.add(version)
                break

    version = None

    for current_version in (all_versions - dead_versions):
        if version is None or current_version > version:
            version = current_version

    return version
