import requests

from dss import Config
from dss.error import DSSForbiddenException, DSSException
from .authorize import Authorize, always_allow_admins


class FlacMixin(Authorize):
    """
    Mixin class for Auth0 Authorize class to use fine-level
    access control (FLAC) table to check if a user is allowed
    to access a given UUID.
    """
    def _assert_authorized_flac(self, **kwargs):
        """
        kwargs contains information from both the original API function
        call and from the security decorator. Use both to look up this
        UUID in the FLAC table.
        """
        # uuid = kwargs['uuid']
        # method = kwargs['method']
        # email = self.token_email
        # group = self.token_group
        # Do FLAC lookup here
        return

class Auth0AuthZGroupsMixin(Authorize):
    """
    Mixin class for Auth0 Authorize class to access groups information
    added to the JWT by the Auth0 AuthZ extension. These are the groups
    used to determine FLAC access.

    (Note: the Auth0 AuthZ extension adds groups, roles, and permissions,
    but here we just use groups.)
    """
    @classmethod
    def get_auth0authz_claim(self):
        oidc_audience = Config.get_audience()[0]
        return f"{oidc_audience}auth0"

    @property
    def auth0authz_groups(self):
        """Property for the groups added to the JWT by the Auth0 AuthZ plugin"""
        # First get the portion of the token added by the Auth0 AuthZ extension
        auth0authz_claim = self.get_auth0authz_claim()
        self._assert_required_token_parameters(self.token, [auth0authz_claim])
        auth0authz_token = self.token[auth0authz_claim]

        # Second extract the groups from this portion
        auth0authz_groups_claim = "groups"
        self.assert_required_parameters(auth0authz_token, [auth0authz_groups_claim])
        groups = self.token[auth0authz_claim][auth0authz_groups_claim]
        return groups

    def assert_auth0authz_groups_intersects(self, groups):
        """
        Assert that the intersection of Auth0 AuthZ groups and user-provided groups
        has cardinality greater than zero (intersection has at least 1 member).
        """
        cardinality = len(set(self.auth0authz_groups).intersection(set(groups)))
        return cardinality > 0


class Auth0(FlacMixin, Auth0AuthZGroupsMixin):
    """
    Implements the Auth0 security flow, which implements different
    authorization checks based on whether operations are
    create/read/update/delete operations.

    Decorator examples:
    @security.assert_security(method='create', groups=['dbio', 'grp'])
    @security.assert_security(method='read')
    @security.assert_security(method='update', groups=['dbio', 'grp'])
    @security.assert_security(method='delete')
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

    @always_allow_admins
    def _create(self, **kwargs):
        """Auth checks for 'create' API actions"""
        # Only check that the token group is in the security decorator's list of allowed groups
        self.assert_required_parameters(kwargs, ['groups'])
        self._assert_authorized_group(kwargs['groups'])
        return

    @always_allow_admins
    def _read(self, **kwargs):
        """Auth checks for 'read' API actions"""
        # Data is public if there is no FLAC table entry.
        self._assert_authorized_flac(**kwargs)
        return

    @always_allow_admins
    def _update(self, **kwargs):
        """Auth checks for 'update' API actions"""
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
        return

    @always_allow_admins
    def _delete(self, **kwargs):
        """Auth checks for 'delete' API actions"""
        err = "Delete action is only allowed for admin users"
        raise DSSForbiddenException(err)
