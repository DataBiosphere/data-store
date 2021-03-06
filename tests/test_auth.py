#!/usr/bin/env python
import io
import os
import sys
import unittest
from unittest import mock

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # noqa
sys.path.insert(0, pkg_root)  # noqa

import dss
from dss import DSSException, DSSForbiddenException, Config
from dss.util.auth import AuthWrapper
from dss.util.auth.authorize import \
    (AuthorizeBase, TokenMixin, TokenGroupMixin, TokenEmailMixin, AdminStatusMixin, always_allow_admins)
from dss.util.auth.auth0 import (FlacMixin, Auth0AuthZGroupsMixin)
from tests.infra import testmode
from tests import get_service_jwt, UNAUTHORIZED_GCP_CREDENTIALS


def get_token_issuer_claim(iss: str) -> dict:
    token = {}
    token['iss'] = iss
    return token


def get_token_email_claim(eml: str, iss: str = '') -> dict:
    token = get_token_issuer_claim(iss)
    token[Config.get_OIDC_email_claim()] = eml
    return token


def get_token_group_claim(grp: str, eml: str = '', iss: str = '') -> dict:
    token = get_token_email_claim(eml, iss)
    token[Config.get_OIDC_group_claim()] = grp
    return token


def get_token_auth0_claim(grp: str, auth0authzgrp: str, eml: str = '', iss: str = '') -> dict:
    """
    Add a claim at {OIDC_AUDIENCE}/auth0 to mimick what the Auth0 AuthZ extension adds.
    User must specify both token group (grp) and Auth0 AuthZ group (auth0authzgrp).
    """
    token = get_token_group_claim(grp, eml, iss)
    auth0claim = Auth0AuthZGroupsMixin.get_auth0authz_claim()
    token[auth0claim] = {
        "groups": [auth0authzgrp],
        "roles": [],
        "permissions": []
    }
    return token


def get_token_admin_claim() -> dict:
    token = get_token_issuer_claim('')
    admin_user_emails = Config.get_admin_user_emails()
    token[Config.get_OIDC_email_claim()] = admin_user_emails[0]
    return token


class TestAuthBase(unittest.TestCase):
    """
    Test security flow and supporting methods in base Authorize class and all mixins.
    """
    @classmethod
    def setUpClass(cls):
        dss.Config.set_config(dss.BucketConfig.TEST)

    def test_base_auth_security_flow(self):
        # Virtual methods gonna virtual
        a = AuthorizeBase()
        with self.assertRaises(NotImplementedError):
            a.security_flow()

    def test_base_assert_required_parameters(self):
        params = {
            'foo': 'bar',
            'baz': 'wuz'
        }
        a = AuthorizeBase()
        a.assert_required_parameters(params, ['foo', 'baz'])


class TestAuthMixins(unittest.TestCase):
    """
    Test the various mixins defined for Authorize classes
    """
    @classmethod
    def setUpClass(cls):
        dss.Config.set_config(dss.BucketConfig.TEST)

    def test_token_mixin(self):
        tm = TokenMixin()
        valid_token = get_token_issuer_claim(Config.get_openid_provider())
        invalid_token = get_token_issuer_claim("invalid-issuer-auth_dss_test-auth_test-token-mixin")
        with mock.patch('dss.util.auth.authorize.TokenMixin.token', valid_token):
            self.assertEquals(tm.token, valid_token)
            tm._assert_authorized_issuer()
        with mock.patch('dss.util.auth.authorize.TokenMixin.token', invalid_token):
            self.assertEquals(tm.token, invalid_token)
            with self.assertRaises(DSSException):
                tm._assert_authorized_issuer()

    def test_token_group_mixin(self):
        tgm = TokenGroupMixin()
        valid_group = 'dbio'
        valid_token = get_token_group_claim(valid_group)
        invalid_token = get_token_group_claim("invalid-group_dss_test-auth_test-token-group-mixin")
        with mock.patch('dss.util.auth.authorize.TokenGroupMixin.token', valid_token):
            tgm._assert_authorized_group([valid_group])
        with mock.patch('dss.util.auth.authorize.TokenGroupMixin.token', invalid_token):
            with self.assertRaises(DSSException):
                tgm._assert_authorized_group([valid_group])

    def test_token_email_mixin(self):
        tem = TokenEmailMixin()
        valid_email = 'valid-email@dss_test-auth_test-token-email-mixin'
        invalid_email = 'invalid-email@dss_test-auth_test-token-email-mixin'
        valid_token = get_token_email_claim(valid_email)
        invalid_token = get_token_email_claim(invalid_email)
        with mock.patch('dss.util.auth.authorize.TokenEmailMixin.token', valid_token):
            tem._assert_authorized_email([valid_email])
        with mock.patch('dss.util.auth.authorize.TokenEmailMixin.token', invalid_token):
            with self.assertRaises(DSSException):
                tem._assert_authorized_email([valid_email])

    def test_admin_status_mixin(self):
        asm = AdminStatusMixin()
        admin_email = asm.admin_emails[0]
        admin_token = get_token_email_claim(admin_email)
        notadmin_token = get_token_email_claim('not-an-admin@dss_test-auth_test-admin-mixin')
        with mock.patch('dss.util.auth.authorize.AdminStatusMixin.token', admin_token):
            self.assertTrue(asm._is_admin())
        with mock.patch('dss.util.auth.authorize.AdminStatusMixin.token', notadmin_token):
            self.assertFalse(asm._is_admin())

    def test_flac_mixin(self):
        FlacMixin()

    def test_auth0authz_mixin(self):
        # Test class method to return the Auth0 claim
        ok_claim = f"{Config.get_audience()[0]}auth0"
        self.assertTrue(Auth0AuthZGroupsMixin.get_auth0authz_claim(), ok_claim)
        # Create a token with the correct Auth0 claim
        a0az = Auth0AuthZGroupsMixin()
        valid_group = 'dbio'
        valid_auth0authz_group = 'foobar'
        invalid_auth0authz_group = 'not-foobar'
        valid_token = get_token_auth0_claim(valid_group, valid_auth0authz_group)
        with mock.patch('dss.util.auth.auth0.Auth0AuthZGroupsMixin.token', valid_token):
            # Test access to A0AZ groups attribute
            self.assertEqual(a0az.auth0authz_groups, [valid_auth0authz_group])
            # Test ability to determine if A0AZ groups intersect a provided list
            all_groups = [valid_auth0authz_group, invalid_auth0authz_group]
            a0az.assert_auth0authz_groups_intersects(all_groups)


class TestFusilladeAuth(unittest.TestCase):
    """
    Test security flow for Fusillade authentication and authorization layer.
    """
    def test_authorized_security_flow(self):
        valid_grp = 'dbio'
        valid_token = get_token_group_claim(valid_grp)
        self._test_security_flow(valid_token, valid_grp)

    def test_unauthorized_security_flow(self):
        valid_grp = 'dbio'
        invalid_grp = 'not-a-valid-grp_dss_test-auth_test-fusillade'
        invalid_token = get_token_group_claim(invalid_grp)
        with self.assertRaises(DSSException):
            self._test_security_flow(invalid_token, valid_grp)

    def _test_security_flow(self, token: dict, allowed_grp: str):
        with mock.patch('dss.util.auth.authorize.Authorize.token', token):
            # Test that security flow succeeds for each auth backend
            with mock.patch("dss.Config.get_auth_backend", return_value="fusillade"):
                auth = AuthWrapper()
                auth.security_flow(groups=[allowed_grp])  # type: ignore


class TestAuth0Auth(unittest.TestCase):
    """
    Test security flow for Auth0 authentication and authorization layer.
    """
    def test_authorized_security_flow(self):
        """
        Create a token with a valid group claim, and run through the normal security flow to check for
        a valid group claim.
        """
        valid_grp = 'dbio'
        valid_token = get_token_group_claim(valid_grp)
        self._test_security_flow(valid_token, valid_grp)

    def test_unauthorized_security_flow(self):
        valid_grp = 'dbio'
        invalid_grp = 'not-a-valid-group_dss_test-auth_test-auth0'
        invalid_token = get_token_group_claim(invalid_grp)
        with self.assertRaises(DSSException):
            self._test_security_flow(invalid_token, valid_grp)

    def test_admin_security_flow(self):
        """
        Create a token for an admin user, and run through the security flow to verify admins are allowed
        to do all actions.
        """
        admin_token = get_token_admin_claim()
        self._test_security_flow(admin_token, '', admin=True)
        self._test_security_flow(admin_token, 'dbio', admin=True)
        self._test_security_flow(admin_token, 'any-group-should-work', admin=True)

    def _test_security_flow(self, token, allowed_grp, admin=False):
        """
        Private method: given a token and an allowed group, use the token to mock the Authorize class,
        then test the security flow.

        :param token: the token to use to mock Authorize.token
        :param allowed_grp: use this group as the allowed group during the security flow
        :param bool admin: is this user an admin? or will admin endpoints raise exceptions?
        """
        with mock.patch("dss.Config.get_auth_backend", return_value="auth0"):
            with mock.patch('dss.util.auth.authorize.Authorize.token', token):
                auth = AuthWrapper()
                auth.security_flow(method='create', groups=[allowed_grp])  # type: ignore
                auth.security_flow(method='group', groups=[allowed_grp])  # type: ignore
                with mock.patch('dss.util.auth.auth0.FlacMixin._assert_authorized_flac', return_value=True):
                    auth.security_flow(method='read')  # type: ignore
                    auth.security_flow(method='update', groups=[allowed_grp])  # type: ignore
                if admin:
                    auth.security_flow(method='delete')  # type: ignore
                else:
                    with self.assertRaises(DSSForbiddenException):
                        auth.security_flow(method='delete')  # type: ignore


if __name__ == "__main__":
    unittest.main()
