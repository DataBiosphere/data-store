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
from tests.infra import testmode


class TestAuth(unittest.TestCase):
    """Test security flow for each Authorize class in dss.util.auth"""

    @classmethod
    def setUpClass(cls):
        dss.Config.set_config(dss.BucketConfig.TEST)

    def test_authorized_group(self):
        valid_token = {os.environ['OIDC_GROUP_CLAIM']: 'dbio'}
        with mock.patch('dss.util.auth.authorize.Authorize.token', valid_token):

            # Test that security flow succeeds for each auth backend
            with mock.patch("dss.Config.get_auth_backend", return_value="fusillade"):
                auth = AuthWrapper()
                auth.security_flow(['dbio'])
            with mock.patch("dss.Config.get_auth_backend", return_value="auth0"):
                auth = AuthWrapper()
                auth.security_flow('create', ['dbio'])

    def test_unauthorized_group(self):
        invalid_token = {}
        with mock.patch('dss.util.auth.authorize.Authorize.token', invalid_token):

            # Test that security flow fails for each auth backend
            with mock.patch("dss.Config.get_auth_backend", return_value="fusillade"):
                # Check failure due to empty token
                with self.assertRaises(DSSForbiddenException):
                    auth = AuthWrapper()
                    auth.security_flow(['dbio'])

                # Check failure due to invalid method signature
                with self.assertRaises(RuntimeError):
                    auth = AuthWrapper()
                    auth.security_flow()

if __name__ == "__main__":
    unittest.main()
