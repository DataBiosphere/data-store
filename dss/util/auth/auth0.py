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
                              'delete': self._delete}

    def security_flow(self, **kwargs):
        """
        Dispatch pattern: the assert_security decorator will specify
        the type of operation (CRUD), which is passed through to the
        kwargs of this method, and used to call the correct method.
        """
        #  TODO add some type of jwt inspection
        self.assert_required_parameters(kwargs, 'method')
        method = kwargs['method']

        # Ensure method is valid
        if method is None or method not in self.valid_methods.keys():
            err = f'Unable to locate auth_method {method} for request, valid methods are: '
            err += f'{", ".join(self.valid_methods)}'
            raise DSSException(500, err)

        # Further kwarg processing should happen from
        # inside the method that needs the info.

        # Dispatch to correct method
        executed_method = self.valid_methods[method]
        executed_method(**kwargs)

    def _create(self, **kwargs):
        """Auth checks for any 'create' API endpoint actions"""
        self.assert_required_parameters(kwargs, ['groups'])
        groups = kwargs['groups']
        self._assert_authorized_group(groups)
        return

    def _read(self, **kwargs):
        # Data is public by default
        pass

        # Eventually we will do a FLAC lookup first.
        # If FLAC lookup doesn't raise exceptions,
        # the requested read access will be granted.

        # args/kwargs should include args/kwargs from
        # both the decorator and the decorated function,
        # so that's how we can get requested UUID

    def _update(self, **kwargs):
        # Requires checking ownership of UUID
        pass

    def _delete(self, **kwargs):
        # Requires checking ownership of UUID
        pass
