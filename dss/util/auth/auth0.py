import requests

from dss.error import DSSForbiddenException, DSSException
from .authorize import Authorize


class FlacMixin(Authorize):
    def _assert_authorized_flac(self, **kwargs):
        uuid = kwargs['uuid']
        method = kwargs['method']
        email = self.token_email
        group = self.token_group
        # Do FLAC lookup here
        return


class Auth0(FlacMixin):
    """
    Implements the Auth0 security flow, which implements different
    authorization checks based on whether operations are
    create/read/update/delete operations.

    Decorator examples:
    @security.assert_authorize(method='create', groups=['dbio', 'grp'])
    @security.assert_authorize(method='read')
    @security.assert_authorize(method='update', groups=['dbio', 'grp'])
    @security.assert_authorize(method='delete')
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
        self.assert_required_parameters(kwargs, ['method'])
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
        """Auth checks for 'create' API actions"""
        # Only check that a user is a member of a list of allowed organizations
        self.assert_required_parameters(kwargs, ['groups'])
        self._assert_authorized_group(kwargs['groups'])
        return

    def _read(self, **kwargs):
        """Auth checks for 'read' API actions"""
        # Data is public if there is no FLAC table entry.
        self._assert_authorized_flac(**kwargs)
        return

    def _update(self, **kwargs):
        """Auth checks for 'update' API actions"""
        try:
            # Admins are always allowed to update
            self._assert_admin(**kwargs)
            return
        except DSSException:
            # Update requires read and create access
            # Assert user has read access
            read_kwargs = kwargs.copy()
            read_kwargs['method'] = 'read'
            self._read(**read_kwargs)

            # Assert user has create access
            create_kwargs = kwargs.copy()
            create_kwargs['method'] = 'create'
            self.assert_required_parameters(create_kwargs, ['groups'])
            self._create(**create_kwargs)
        pass

    def _delete(self, **kwargs):
        """Auth checks for 'delete' API actions"""
        # Only admins allowed
        self._assert_admin(**kwargs)
