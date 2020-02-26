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
        This method maps out security flow for Auth with Fusillade
        Current implimentation of Fusillade 2.0 requires principals, actions, and resources
        for all evaluation requests
        """
        # Get token
        decorator_kwargs['security_token'] = request.token_info

        # Set security_groups using first argument, if kwarg not present
        if kwargs.get('security_groups') is None:
             kwargs['security_groups'] = args[0]

        # Verify JWT was populated correctly
        self.assert_required_parameters(kwargs, ['security_groups', 'security_token'])
        groups = kwargs.get('security_groups')
        token = kwargs.get('security_token')
        self.assert_authorized_group(groups, token)

        return  # we actually dont want to use this evaluation method at the moment, so just skip.
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

    def assert_authorized_group(self, group: typing.List[str], token: dict) -> None:
        if token.get(Config.get_OIDC_group_claim()) in group:
            return
        logger.info(f"User not in authorized group: {group}, {token}")
        raise DSSForbiddenException()
