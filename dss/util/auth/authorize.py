import typing

from dss.util.auth import authregistry


class Authorize(metaclass=authregistry.AuthRegistry):
    """ abstract class for authorization classes"""
    def __init__(self):
        pass

    def security_flow(self, authz_methods: typing.List[str], *args, **kwargs):
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
                raise Exception('unable to use Authorization method, missing required parameters')
        return
