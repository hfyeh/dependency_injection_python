from app import IFailedCounter, FailedTooManyTimesError
from app.authentication_service import AuthenticationBaseDecorator, IAuthenticationService


class FailedCounterDecorator(AuthenticationBaseDecorator):
    def __init__(self, authentication_service: IAuthenticationService, failed_counter: IFailedCounter):
        super().__init__(authentication_service)
        self._failed_counter = failed_counter

    def check_account_is_locked(self, username):
        if self._failed_counter.is_account_locked(username):
            raise FailedTooManyTimesError()

    def reset(self, username):
        self._failed_counter.reset(username)

    def verify(self, username: str, password: str, otp: str) -> bool:
        self.check_account_is_locked(username)

        is_valid = super().verify(username, password, otp)
        if is_valid:
            self.reset(username)

        return is_valid
