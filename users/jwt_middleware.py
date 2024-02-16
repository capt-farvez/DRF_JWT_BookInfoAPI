# jwt_middleware.py

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import exceptions

class JWTMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_authentication = JWTAuthentication()

    def __call__(self, request):
        # Check if the request is excluded from JWT authentication
        if not request.path_info.startswith('/api/token/') and not request.path_info.startswith('/user/register/'):
            try:
                # Authenticate the request using JWTAuthentication
                authentication = self.jwt_authentication.authenticate(request)
                if authentication is not None:
                    request.user = authentication[0]
            except exceptions.AuthenticationFailed:
                # Raise AuthenticationFailed exception if authentication fails
                raise exceptions.AuthenticationFailed('Invalid token')

        # Continue processing the request
        response = self.get_response(request)
        return response
