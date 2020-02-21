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
    """
    def __init__(self):
        self.session = requests.Session()

    def security_flow(self, authz_methods: typing.List[str], *args, **kwargs):
        """
        This method maps out security flow for Auth with Fusillade
        """
        if 'evaluate' in authz_methods:
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
