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


def get_token_issuer_claim_ok(iss):
    return {'iss': iss}

def get_token_group_claim_ok(grp):
    return {Config.get_OIDC_group_claim(): grp}


def get_token_email_claim_ok(eml):
    return {Config.get_OIDC_email_claim(): eml}


def get_token_admin_claim_ok():
    admin_user_emails = Config.get_admin_user_emails()
    return {Config.get_OIDC_email_claim(): admin_user_emails[0]}


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
        valid_token = get_token_issuer_claim_ok(Config.get_openid_provider())
        invalid_token = get_token_issuer_claim_ok("dss-testauth-test_token_mixin-invalid_issuer")
        with mock.patch('dss.util.auth.authorize.TokenMixin.token', valid_token):
            self.assertEquals(tm.token, valid_token)
            tm._assert_authorized_issuer()
        with mock.patch('dss.util.auth.authorize.TokenMixin.token', invalid_token):
            self.assertEquals(tm.token, invalid_token)
            with self.assertRaises(DSSException):
                tm._assert_authorized_issuer()

    def test_token_group_mixin(self):
        tgm = TokenGroupMixin()
        grp = 'dbio'
        valid_token = get_token_group_claim_ok(grp)
        invalid_token = get_token_group_claim_ok('boo-this-is-an-invalid-token-group')
        with mock.patch('dss.util.auth.authorize.TokenGroupMixin.token', valid_token):
            tgm._assert_authorized_group([grp])
        with mock.patch('dss.util.auth.authorize.TokenGroupMixin.token', invalid_token):
            with self.assertRaises(DSSException):
                tgm._assert_authorized_group([grp])

    def test_token_email_mixin(self):
        tem = TokenEmailMixin()
        eml = 'valid-email@dss-testauth-test_token_email_mixin.ucsc-cgp-redwood.org'
        valid_token = get_token_email_claim_ok(eml)
        invalid_token = get_token_email_claim_ok(f'not-a-valid-email')
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
        valid_grp = 'dbio'
        valid_token = get_token_group_claim_ok(valid_grp)
        with mock.patch('dss.util.auth.authorize.Authorize.token', valid_token):

            # Test that security flow succeeds for each auth backend
            with mock.patch("dss.Config.get_auth_backend", return_value="fusillade"):
                auth = AuthWrapper()
                auth.security_flow(groups=[valid_grp])

    def test_unauthorized_security_flow(self):
        invalid_token = {}
        with mock.patch('dss.util.auth.authorize.Authorize.token', invalid_token):
            # Set auth backend
            with mock.patch("dss.Config.get_auth_backend", return_value="fusillade"):
                valid_grp = 'dbio'
                # Check failure due to empty token
                with self.assertRaises(DSSForbiddenException):
                    auth = AuthWrapper()
                    auth.security_flow(groups=[valid_grp])
                # Check failure due to invalid method signature
                with self.assertRaises(DSSException):
                    auth = AuthWrapper()
                    auth.security_flow()

if __name__ == "__main__":
    unittest.main()
