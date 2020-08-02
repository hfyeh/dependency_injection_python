from app import INotification
from app.authentication_service import IAuthenticationService


class AuthenticationBaseDecorator(IAuthenticationService):
    def __init__(self, authentication_service: IAuthenticationService):
        self._authentication_service = authentication_service

    def verify(self, username: str, password: str, otp: str) -> bool:
        return self._authentication_service.verify(username, password, otp)


class NotificationDecorator(AuthenticationBaseDecorator):
    def __init__(self, authentication_service: IAuthenticationService, notification: INotification):
        super().__init__(authentication_service)
        self._notification = notification

    def notify(self, username):
        self._notification.notify(username)

    def verify(self, username: str, password: str, otp: str) -> bool:
        is_valid = super().verify(username, password, otp)
        if not is_valid:
            self.notify(username)

        return is_valid
