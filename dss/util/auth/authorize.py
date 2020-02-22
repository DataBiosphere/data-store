import typing
import logging

from dss.config import Config
from dss.error import DSSForbiddenException, DSSException
from . import authregistry

logger = logging.getLogger(__name__)


class Authorize(metaclass=authregistry.AuthRegistry):
    """ abstract class for authorization classes"""
    def __init__(self):
        pass

    def security_flow(self, *args, **kwargs):
        """
        This function maps out flow for a given security config
        Be sure to call it from the derived class to ensure the JWT has groups set
        """
        groups = kwargs.get('security_groups')
        token = kwargs.get('security_token')
        if groups is not None and token is not None:
            self.assert_authorized_group(groups, token)
        else:
            title = "security_groups not found"
            err = f'Error with jwt group validation, unable to locate required security groups,'
            err += f' please ensure kwarg: "security_groups"" is set within the assert_security decorator'
            raise DSSException(500, title, err)

    def assert_required_parameters(self, provided_params: dict, required_params: list):
        """
        Ensures existence of parameters in dictionary passed
        :param provided_params: dictionary that contains arbitrary parameters
        :param required_params: list of parameters that we want to ensure exist

        """
        for param in required_params:
            if param not in provided_params:
                raise Exception('unable to use Authorization method, missing required parameters')
        return

    def assert_authorized_group(self, group: typing.List[str], token: dict) -> None:
        if token.get(Config.get_OIDC_group_claim()) in group:
            return
        logger.info(f"User not in authorized group: {group}, {token}")
        raise DSSForbiddenException()
