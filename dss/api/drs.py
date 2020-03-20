import os
import requests

from flask import jsonify, make_response, request

from dss import dss_handler
from dss.api.files import get_helper
from dss.config import Replica
from dss.util.version import datetime_from_timestamp


@dss_handler
def get_data_object(object_id: str):
    """
    Translates a DRS data object request to a DSS GET/HEAD file request.
    See the Data Repository Service schema here:
    https://ga4gh.github.io/data-repository-service-schemas/preview/release/drs-1.0.0/docs/
    """
    # This only implements file access for now. As such, `expand` is ignored
    version = request.args.get("version", None)
    replica = request.args.get("replica", "aws")
    req = get_helper(object_id, replica=Replica[replica], version=version)
    if req.status_code == 301:
        req.status_code = 202
        return req
    elif req.status_code != 302:  # For errors, just proxy DSS response
        return req
    version = (f'&version={version}' if version is not None else '')
    self_url = f"drs://{os.environ['API_DOMAIN_NAME']}/v1/ga4gh/drs/v1/objects/{object_id}?replica={replica}" + version
    resp = {
        'checksums': [
            {'checksum': req.headers['x-dss-sha1'],
             'type': 'sha1'},
            {'checksum': req.headers['x-dss-sha256'],
             'type': 'sha256'},
            {'checksum': req.headers['x-dss-s3-etag'],
             'type': 's3-etag'},
            {'checksum': req.headers['x-dss-crc32c'],
             'type': 'crc32c'}
        ],
        'access_methods': [{
            'type': 's3' if replica == 'aws' else 'gcp',
            'access_url': {
                'url': req.headers['Location']
            }
        }],
        'created_time': datetime_from_timestamp(req.headers['x-dss-version']),
        'updated_time': datetime_from_timestamp(req.headers['x-dss-version']),
        'id': object_id,
        'name': object_id,
        'self_uri': self_url,
        'size': int(req.headers['x-dss-size']),
        'version': req.headers['x-dss-version'],
        'mime_type': req.headers['x-dss-content-type'],
    }
    return make_response(jsonify(resp), requests.codes.ok)
