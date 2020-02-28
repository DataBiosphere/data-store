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

    def security_flow(self, *args, **kwargs):
        """
        Dispatch pattern: the assert_security decorator will specify
        the type of operation (CRUD), which is passed through to the
        kwargs of this method, and used to call the correct method.
        """
        #  TODO add some type of jwt inspection

        # Get name of method to use
        if 'auth_method' in kwargs:
            method = kwargs['auth_method']
        elif len(args) > 0:
            method = args[0]
            kwargs['auth_method'] = method
        else:
            raise RuntimeError("Error: invalid arguments passed to Auth0 security_flow() method")

        # Ensure method is valid
        if method is None or method not in self.valid_methods.keys():
            err = f'Unable to locate auth_method {method} for request, valid methods are: '
            err += f'{", ".join(self.valid_methods)}'
            raise DSSException(500, err)

        # Any further kwarg processing should happen
        # from inside the method that needs that info,
        # to limit specifications.

        # Dispatch to correct method
        executed_method = self.valid_methods[method]
        executed_method(*args, **kwargs)

    def _create(self, *args, **kwargs):
        """Auth checks for any 'create' API endpoint actions"""
        # Get name of allowed groups (either security_groups kwarg or second positional arg)
        if 'security_groups' in kwargs:
            groups = kwargs['security_groups']
        elif len(args) > 1:
            groups = args[1]
            kwargs['security_groups'] = groups
        else:
            raise RuntimeError("Error: invalid arguments passed to Auth0 security_flow() method")

        self._assert_authorized_group(groups)
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
