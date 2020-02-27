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
    """Test each Authorize class in dss.util.auth"""

    @classmethod
    def setUpClass(cls):
        dss.Config.set_config(dss.BucketConfig.TEST)

    def test_authorized_group(self):
        valid_token = {os.environ['OIDC_GROUP_CLAIM']: 'dbio'}
        with mock.patch("dss.Config.get_auth_backend", return_value="fusillade"):
            with mock.patch('dss.util.auth.authorize.Authorize.token', valid_token):
                auth = AuthWrapper()
                auth.security_flow(['dbio'])

    @mock.patch('dss.Config.get_auth_backend', new=lambda : 'fusillade')
    def test_unauthorized_group(self):
        invalid_token = {}
        with mock.patch("dss.Config.get_auth_backend", return_value="fusillade"):
            with mock.patch('dss.util.auth.authorize.Authorize.token', invalid_token):
                with self.assertRaises(DSSForbiddenException):
                    auth = AuthWrapper()
                    auth.security_flow(['dbio'])

if __name__ == "__main__":
    unittest.main()
