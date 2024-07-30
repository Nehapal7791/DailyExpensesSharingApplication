from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

class CookieTokenAuthentication(TokenAuthentication):
    def authenticate(self, request):
        # Check the header for the token
        auth = super().authenticate(request)
        if auth is not None:
            return auth

        # If no token is found in the header, check the cookies
        token = request.COOKIES.get('auth_token')
        if not token:
            return None

        try:
            user, token = self.authenticate_credentials(token)
        except AuthenticationFailed:
            return None

        return (user, token)
