import requests

from dss.error import DSSForbiddenException, DSSException
from . import authorize


class Auth0(authorize.Authorize):
    def __init__(self):
        self.session = requests.Session()
        self.valid_methods = {'create': self._create,
                              'destroy': self._destroy,
                              'update': self._update,
                              'read': self._read}

    def security_flow(self, *args, **kwargs):
        requested_method = kwargs.get('auth_method').lower()
        if requested_method is None or requested_method not in self.valid_methods.keys():
            raise DSSException(500, 'Unable to locate auth_method for request')
        else:
            executed_method = self.valid_methods[requested_method]
            executed_method(*args, **kwargs)

    def _read(self, *args, **kwargs):
        pass

    def _write(self, *args, **kwargs):
        pass

    def _create(self, *args, **kwargs):
        pass

    def _update(self, *args, **kwargs):
        pass
