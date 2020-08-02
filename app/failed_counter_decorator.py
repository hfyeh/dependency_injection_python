from app import IFailedCounter, FailedTooManyTimesError
from app.authentication_service import AuthenticationBaseDecorator, IAuthenticationService


class FailedCounterDecorator(AuthenticationBaseDecorator):
    def __init__(self, authentication_service: IAuthenticationService, failed_counter: IFailedCounter):
        super().__init__(authentication_service)
        self._failed_counter = failed_counter

    def check_account_is_locked(self, username):
        if self._failed_counter.is_account_locked(username):
            raise FailedTooManyTimesError()

    def verify(self, username: str, password: str, otp: str) -> bool:
        self.check_account_is_locked(username)
        return super().verify(username, password, otp)