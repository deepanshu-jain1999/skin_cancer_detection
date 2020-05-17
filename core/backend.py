from django.contrib.auth.backends import ModelBackend

from .models import User


class UserEmailBackend(ModelBackend):
    def get_through_email(self, username, password):
        try:
            user = User.objects.get(email=username)
            # print(user)
        except User.DoesNotExist:
            return None
        else:
            if user.check_password(password):
                return user
        return None

    def get_through_username(self, username, password):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None
        else:
            if user.check_password(password):
                return user
        return None

    def authenticate(self, request, username=None, password=None, **kwargs):
        user = self.get_through_email(username, password)
        if user:
            return user
        user = self.get_through_username(username, password)
        return user
