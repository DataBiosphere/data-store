import typing
import logging
import requests
from flask import request

from dss import Config
from dss.error import DSSForbiddenException, DSSException
from .authregistry import AuthRegistry

logger = logging.getLogger(__name__)


"""
Authorize class:

The Authorize class is defined at the bottom.
We define a base class and multiple mixins,
and use those to compose the final Authorize
class.
"""


class AuthorizeBase(metaclass=AuthRegistry):
    """
    Base class for authentication/authorization methods.
    This class exists solely to wrap the definition of the assert security flow.
    Subclasses must define a security_flow method.
    All subclasses inherit from AuthRegistry and are added to a registry on definition.
    """
    def __init__(self):
        pass

    def security_flow(self, *args, **kwargs):
        """
        This function maps out flow for a given security config
        """
        raise NotImplementedError()

    def assert_required_parameters(self, provided_params: dict, required_params: list):
        """
        Ensures existence of parameters in dictionary passed

        :param provided_params: dictionary that contains arbitrary parameters
        :param required_params: list of parameters that we want to ensure exist
        """
        for param in required_params:
            if param not in provided_params:
                title = "Missing Security Paramters"
                err = f'Missing parameters within {provided_params.keys()}, unable to locate {param},'
                raise DSSException(500, title, err)
        return


class TokenMixin(AuthorizeBase):
    """
    Mixin: add a token property that
    returns the JWT for the user's session.
    Includes verification methods.
    """
    @property
    def token(self):
        """Property for the user's JWT token"""
        return request.token_info

    def _assert_authorized_issuer(self):
        """Assert the token issuer matches valid issuers in DSS config"""
        from ..security import assert_authorized_issuer
        assert_authorized_issuer(self.token)
        return


class TokenGroupMixin(TokenMixin):
    """
    Mixin: add a token_group attribute,
    based on group claim set in DSS config.
    Includes verification methods.
    """
    @property
    def token_group(self):
        """Property for the user's JWT group claim"""
        group_claim = Config.get_OIDC_group_claim()
        return self.token[group_claim]

    def _assert_authorized_group(self, groups):
        """Verify user JWT token group matches specified groups""" from ..security import assert_authorized_group
        from ..security import assert_authorized_group
        assert_authorized_group(groups, self.token)
        return


class TokenEmailMixin(TokenMixin):
    """
    Mixin: add a token_email attribute,
    based on email token claim set in DSS config.
    Includes verification methods.
    """
    @property
    def token_email(self):
        """Property for the user's JWT email claim"""
        email_claim = Config.get_OIDC_email_claim()
        return self.token[email_claim]

    def _assert_authorized_email(self, emails):
        """Verify user JWT token email matches specified emails"""
        from ..security import assert_authorized_email
        assert_authorized_email(groups, self.token)
        return


class Authorize(TokenGroupMixin, TokenEmailMixin):
    pass
