import logging
import typing
import requests

from dss import Config
from dss.error import DSSForbiddenException
from .authorize import Authorize


logger = logging.getLogger(__name__)


class Fusillade(Authorize):
    """
    This class defines the Fusillade security flow.

    security_flow method keyword arguments:
    groups : list of allowed groups

    Example:
    @assert_security(groups = ['dbio', 'myothrgrp'])
    def put(...)
    """
    def __init__(self):
        self.session = requests.Session()

    def security_flow(self, **kwargs):
        """
        This method maps out security flow for Auth with Fusillade.
        We are not using Fusillade 2.x /evaluate endpoint, which would
        require principals actions, and resources. Instead, we go for
        a simpler check that the user's token group claim is in one of
        the allowed groups.
        """
        self.assert_required_parameters(kwargs, ['groups'])
        self._assert_authorized_group(kwargs['groups'])
        return

        # If using Fusillade's /evaluate endpoint:
        self.assert_required_parameters(kwargs, ['principal', 'actions', 'resource'])
        self.assert_authorized(kwargs['principal'], kwargs['actions'], kwargs['resources'])

    def assert_authorized(self, principal: str,
                          actions: typing.List[str],
                          resources: typing.List[str]):
        resp = self.session.post(f"{Config.get_authz_url()}/v1/policies/evaluate",
                                 headers=Config.get_ServiceAccountManager().get_authorization_header(),
                                 json={"action": actions,
                                       "resource": resources,
                                       "principal": principal})
        resp.raise_for_status()
        resp_json = resp.json()
        if not resp_json.get('result'):
            raise DSSForbiddenException(title=f"User is not authorized to access this resource:\n{resp_json}")
