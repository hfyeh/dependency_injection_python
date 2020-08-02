from app import ILogging, IFailedCounter
from app.authentication_service import AuthenticationBaseDecorator, IAuthenticationService


class LoggingDecorator(AuthenticationBaseDecorator):
    def __init__(self, authentication_service: IAuthenticationService, logging: ILogging,
                 failed_counter: IFailedCounter):
        super().__init__(authentication_service)
        self._logging = logging
        self._failed_counter = failed_counter

    def log_message(self, username):
        failed_count = self._failed_counter.get(username)
        self._logging.info(f'user: {username} failed times: {failed_count}')

    def verify(self, username: str, password: str, otp: str) -> bool:
        is_valid = super().verify(username, password, otp)

        if not is_valid:
            self.log_message(username)

        return is_valid