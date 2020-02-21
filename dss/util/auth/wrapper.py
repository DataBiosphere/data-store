from dss import Config
from dss.error import DSSException

from .authregistry import AuthRegistry
from .authorize import Authorize
from .fusillade import Fusillade


class AuthWrapper(object):
    """
    This class transparently wraps whatever Authorize class the user needs.

    AuthWrapper is used in dss.util.security for doing security assertions.
    It uses the AuthRegistry class's registry and the auth handler specified
    in the config file to instantiate the correct Authorize class.
    """
    def __new__(cls, *args, **kwargs):
        """
        Get name of Authorize subclass the user wants, verify it is a registered auth handler,
        create an instance of it, and return the instance.

        We don't define this in __init__ bc __init__ cannot return anything, as it automatically
        returns an AuthWrapper object.
        Instead, we do this in __new__, which allows us to return an object of a different type.
        If __new__ returns anything other than the AuthWrapper type, then __init__ is not called.
        """
        auth_backend = Config.get_auth_backend().lower()
        authz_class = AuthRegistry.REGISTRY.get(auth_backend, None)
        if authz_class is None:
            title = "auth_backend_not_found"
            err = f'Error with security handler, unable to locate authorization method {auth_backend},'
            err += f'Available methods are: {",".join(AuthRegistry.REGISTRY)}'
            raise DSSException(500, title, err)
        else:
            # Instantiate the object and return it.
            # Now `wrapper = AuthWrapper()` will return an Authorize instance, not an AuthWrapper instance
            return authz_class(*args, **kwargs)
