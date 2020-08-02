from abc import ABCMeta, abstractmethod

from .failed_counter import FailedCounter, IFailedCounter
from .logging import Logging, ILogging
from .otp_service import OtpService, IOtpService
from .sha_256_adapter import Sha256Adapter, IHash
from .user import User, IUser


class IAuthenticationService(metaclass=ABCMeta):
    @abstractmethod
    def verify(self, username: str, password: str, otp: str) -> bool:
        pass


class AuthenticationBaseDecorator(IAuthenticationService):
    def __init__(self, authentication_service: IAuthenticationService):
        self._authentication_service = authentication_service

    def verify(self, username: str, password: str, otp: str) -> bool:
        return self._authentication_service.verify(username, password, otp)


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


class AuthenticationService(IAuthenticationService):
    def __init__(self, user: IUser = User(), hash: IHash = Sha256Adapter(), otp_service: IOtpService = OtpService(),
                 failed_counter: IFailedCounter = FailedCounter(), logging: ILogging = Logging()):
        self._user: IUser = user
        self._hash: IHash = hash
        self._otp_service: IOtpService = otp_service
        self._failed_counter: IFailedCounter = failed_counter
        self._logging: ILogging = logging
        # self._failed_counter_decorator = FailedCounterDecorator(self, failed_counter)
        self._logging_decorator = LoggingDecorator(self, logging, failed_counter)

    def verify(self, username: str, password: str, otp: str) -> bool:
        # self._failed_counter_decorator.check_account_is_locked(username)

        password_from_db = self._user.get_password(username)

        hashed_password = self._hash.compute(password)

        current_otp = self._otp_service.get_current_otp(username)

        if password_from_db == hashed_password and otp == current_otp:
            return True
        else:
            # self._logging_decorator.log_message(username)

            return False


class FailedTooManyTimesError(OSError):
    def __init__(self, *args, **kwargs):  # real signature unknown
        pass
