import typing
import logging

from dss.config import Config
from dss.error import DSSForbiddenException, DSSException
from .authregistry import AuthRegistry

logger = logging.getLogger(__name__)


class Authorize(metaclass=AuthRegistry):
    """
    Base class for authentication/authorization methods.
    This class exists solely to wrap the definition of the assert security flow.
    Subclasses must define a security_flow method.
    All subclasses inherit from AuthRegistry and are added to a registry on definition.
    """
    def __init__(self):
        pass

    def security_flow(self, *args, **kwargs):
        """
        This function maps out flow for a given security config
        """
        raise NotImplementedError()

    def assert_required_parameters(self, provided_params: dict, required_params: list):
        """
        Ensures existence of parameters in dictionary passed

        :param provided_params: dictionary that contains arbitrary parameters
        :param required_params: list of parameters that we want to ensure exist
        """
        for param in required_params:
            if param not in provided_params:
                title = "Missing Security Paramters"
                err = f'Missing parameters within {provided_params.keys()}, unable to locate {param},'
                raise DSSException(500, title, err)
        return
