import requests

from flask import jsonify, make_response, request

from dss import dss_handler
from dss.api.files import get_helper
from dss.config import Replica
from dss.util.version import datetime_from_timestamp


@dss_handler
def get_data_object(uuid: str):
    """
    Return a DRS data object dictionary for a given DSS file UUID and version.
    If the file is already checked out, we can return a drs_object with a URL
    immediately. Otherwise, we need to send the request through the /access
    endpoint.
    """
    # TODO: version lookup
    with app.test_request_context(f'/files/{uuid}', method=HEAD, headers=request.headers):
        req = get_helper(uuid, replica=Replica['aws'], version=None)
    if req.status_code != 302:
        # For errors, just proxy DSS response
        return req
    # version = (f'&version={version}' if version is not None else '')
    # url = f'{config.dss_endpoint}/files/{uuid}?replica=aws' + version
    access_url = ''
    self_url = ''
    resp = {
        'checksums': [
            {'sha1': req.headers['x-dss-sha1']},
            {'sha-256': req.headers['x-dss-sha256']},
            {'s3-etag': req.headers['x-dss-s3-etag']},
            {'crc32c': req.headers['x-dss-crc32c']},
        ],
        'access_methods': [{
            'type': 's3',
            'access_url': {
                'url': access_url
            }
        }],
        'created_time': datetime_from_timestamp(req.headers['x-dss-version']),
        'updated_time': datetime_from_timestamp(req.headers['x-dss-version']),
        'id': uuid,
        'name': uuid,
        'self_uri': self_url,
        'size': req.headers['x-dss-size'],
        'version': req.headers['x-dss-version'],
        'mime_type': req.headers['x-dss-content-type'],
    }
    return make_response(jsonify(resp), requests.codes.ok)
