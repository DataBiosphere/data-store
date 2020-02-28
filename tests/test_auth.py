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
from dss.util.auth.authorize import (AuthorizeBase, TokenMixin, TokenGroupMixin, TokenEmailMixin)
from tests.infra import testmode


def get_group_claim_token(grp):
    return {os.environ['OIDC_GROUP_CLAIM']: grp}

def get_email_claim_token(eml):
    return {os.environ['OIDC_EMAIL_CLAIM']: eml}

class TestAuthBase(unittest.TestCase):
    """
    Test security flow and supporting methods in base Authorize class and all mixins.
    """
    @classmethod
    def setUpClass(cls):
        dss.Config.set_config(dss.BucketConfig.TEST)

    def test_auth_security_flow(self):
        # Virtual methods gonna virtual
        a = AuthorizeBase()
        with self.assertRaises(NotImplementedError):
            a.security_flow()

    def test_assert_required_parameters(self):
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
        # Check that when you set the token property on
        # a TokenMixin instance, you get the token property
        tm = TokenMixin()
        valid_token = get_group_claim_token('dbio')
        invalid_token = get_group_claim_token('boo-this-is-an-invalid-token-group')
        with mock.patch('dss.util.auth.authorize.TokenMixin.token', valid_token):
            self.assertEquals(tm.token, valid_token)
            self.assertNotEquals(tm.token, invalid_token)

    def test_group_token_mixin(self):
        tgm = TokenGroupMixin()
        grp = 'dbio'
        valid_token = get_group_claim_token(grp)
        invalid_token = get_group_claim_token('boo-this-is-an-invalid-token-group')
        with mock.patch('dss.util.auth.authorize.TokenGroupMixin.token', valid_token):
            tgm._assert_authorized_group([grp])
        with mock.patch('dss.util.auth.authorize.TokenGroupMixin.token', invalid_token):
            with self.assertRaises(DSSException):
                tgm._assert_authorized_group([grp])

    def test_email_token_mixin(self):
        tem = TokenEmailMixin()
        eml = 'valid-email@dss-testauth-testemailtokenmixin.ucsc.edu'
        valid_token = get_email_claim_token(eml)
        invalid_token = get_email_claim_token(f'not-a-valid-email')
        # Check valid and invalid tokens
        with mock.patch('dss.util.auth.authorize.TokenEmailMixin.token', valid_token):
            tem._assert_authorized_email([eml])
        with mock.patch('dss.util.auth.authorize.TokenEmailMixin.token', invalid_token):
            with self.assertRaises(DSSException):
                tem._assert_authorized_email([eml])


class TestFusilladeAuth(unittest.TestCase):
    """
    Test security flow for Fusillade authentication and authorization layer.
    """

    def test_authorized_security_flow(self):
        valid_token = get_group_claim_token('dbio')
        with mock.patch('dss.util.auth.authorize.Authorize.token', valid_token):

            # Test that security flow succeeds for each auth backend
            with mock.patch("dss.Config.get_auth_backend", return_value="fusillade"):
                auth = AuthWrapper()
                auth.security_flow(groups=['dbio'])
            with mock.patch("dss.Config.get_auth_backend", return_value="auth0"):
                auth = AuthWrapper()
                auth.security_flow(method='create', groups=['dbio'])
                auth.security_flow(method='read')
                auth.security_flow(method='update')
                auth.security_flow(method='delete')

    def test_unauthorized_security_flow(self):
        invalid_token = {}
        with mock.patch('dss.util.auth.authorize.Authorize.token', invalid_token):

            # Test that security flow fails for each auth backend
            with mock.patch("dss.Config.get_auth_backend", return_value="fusillade"):
                # Check failure due to empty token
                with self.assertRaises(DSSForbiddenException):
                    auth = AuthWrapper()
                    auth.security_flow(groups=['dbio'])

                # Check failure due to invalid method signature
                with self.assertRaises(DSSException):
                    auth = AuthWrapper()
                    auth.security_flow()

if __name__ == "__main__":
    unittest.main()
