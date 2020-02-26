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

    def security_flow(self, *args, **kwargs):
        """
        This method maps out security flow for Auth with Fusillade.

        The current implementation of Fusillade (2.0+) uses three pieces of information
        to evaluate authorization: principals, actions, and resources.

        However, we have overridden this with a simpler authentication-based
        authorization layer that just checks for membership in a group.
        """
        # verify JWT was populated correctly
        self.assert_required_parameters(kwargs, ['security_groups', 'security_token'])
        groups = kwargs.get('security_groups')
        token = kwargs.get('security_token')

        # Import when this method is called, not when it is defined, to avoid circular imports
        from ..security import assert_authorized_group
        assert_authorized_group(groups, token)

        return

        # If we were using Fusillade's evaluate endpoint,
        # this is where we would extract relevant information
        # from the security decorator.
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
