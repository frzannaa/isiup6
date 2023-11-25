from django.contrib.auth.backends import BaseBackend
from ki.models import User

class CustomUserBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            print("Username: ", username)
            print("Password: ", password)
            user = User.objects.get(username=username)
            print("User: ", user)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
