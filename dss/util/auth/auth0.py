import requests

from dss.error import DSSForbiddenException, DSSException
from .authorize import Authorize


class Auth0(Authorize):
    """
    Implements the Auth0 security flow, which implements different
    authorization checks based on whether operations are
    create/read/update/delete operations.
    """
    def __init__(self):
        self.session = requests.Session()
        self.valid_methods = {'create': self._create,
                              'read': self._read,
                              'update': self._update,
                              'destroy': self._destroy}

    def security_flow(self, *args, **kwargs):
        """
        Assert security decorator should have arguents specifying
        type of operation (CRUD), which will be passed through
        to these args/kwargs, and relay the call to the right method
        in valid_methods.
        """
        #  TODO add some type of jwt inspection
        requested_method = kwargs.get('auth_method').lower()
        if requested_method is None or requested_method not in self.valid_methods.keys():
            err = f'Unable to locate auth_method {requested_method} for request, valid methods are: '
            err += f'{", ".join(self.vaid_methods)}'
            raise DSSException(500, err)
        else:
            executed_method = self.valid_methods[requested_method]
            executed_method(*args, **kwargs)

    def _create(self, *args, **kwargs):
        # Requires checking group
        return

    def _read(self, *args, **kwargs):
        # Data is public by default
        pass

        # Eventually we will do a FLAC lookup first.
        # If FLAC lookup doesn't raise exceptions,
        # the requested read access will be granted.

        # args/kwargs should include args/kwargs from
        # both the decorator and the decorated function,
        # so that's how we can get requested UUID

    def _update(self, *args, **kwargs):
        # Requires checking ownership of UUID
        pass

    def _delete(self, *args, **kwargs):
        # Requires checking ownership of UUID
        pass
