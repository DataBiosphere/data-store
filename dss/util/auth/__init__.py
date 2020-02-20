import logging

from dss import Config
from dss.error import DSSException
from . import fusillade, authregistry

logger = logging.getLogger(__name__)


class AuthHandler:
    def __new__(cls, *args, **kwargs):
        auth_backend = Config.get_auth_backend().lower()
        authz_class = authregistry.AuthRegistry.REGISTRY.get(auth_backend, None)
        if authz_class is None:
            raise DSSException(500, 'Error with Security Handler, unable to locate Auth Handler')
        else:
            return authz_class(*args, **kwargs)
