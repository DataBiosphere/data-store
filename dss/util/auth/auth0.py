import requests

from dss.error import DSSForbiddenException, DSSException
from .authorize import Authorize


class Auth0(Authorize):
    def __init__(self):
        self.session = requests.Session()
        self.valid_methods = {'create': self._create,
                              'destroy': self._destroy,
                              'update': self._update,
                              'read': self._read}

    def security_flow(self, *args, **kwargs):
        #  TODO add some type of jwt inspection
        requested_method = kwargs.get('auth_method').lower()
        if requested_method is None or requested_method not in self.valid_methods.keys():
            err = f'Unable to locate auth_method {requested_method} for request, valid methods are: '
            err += f'{", ".join(self.vaid_methods)}'
            raise DSSException(500, err)
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
