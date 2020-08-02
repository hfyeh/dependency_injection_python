from abc import ABCMeta, abstractmethod

from .failed_counter import FailedCounter, IFailedCounter
from .logging import Logging, ILogging
from .otp_service import OtpService, IOtpService
from .sha_256_adapter import Sha256Adapter, IHash
from .slack_adapter import SlackAdapter, INotification
from .user import User, IUser


class IAuthenticationService(metaclass=ABCMeta):
    @abstractmethod
    def verify(self, username: str, password: str, otp: str) -> bool:
        pass


class AuthenticationService(IAuthenticationService):
    def __init__(self, user: IUser = User(), hash: IHash = Sha256Adapter(), otp_service: IOtpService = OtpService(),
                 failed_counter: IFailedCounter = FailedCounter(), notification: INotification = SlackAdapter(),
                 logging: ILogging = Logging()):
        self._user: IUser = user
        self._hash: IHash = hash
        self._otp_service: IOtpService = otp_service
        self._failed_counter: IFailedCounter = failed_counter
        self._notification: INotification = notification
        self._logging: ILogging = logging

    def verify(self, username: str, password: str, otp: str) -> bool:
        if self._failed_counter.is_account_locked(username):
            raise FailedTooManyTimesError()

        password_from_db = self._user.get_password(username)

        hashed_password = self._hash.compute(password)

        current_otp = self._otp_service.get_current_otp(username)

        if password_from_db == hashed_password and otp == current_otp:
            self._failed_counter.reset(username)

            return True
        else:
            self._failed_counter.add(username)

            self.notify(username)

            failed_count = self._failed_counter.get(username)
            self._logging.info(f'user: {username} failed times: {failed_count}')

            return False

    def notify(self, username):
        self._notification.notify(username)


class FailedTooManyTimesError(OSError):
    def __init__(self, *args, **kwargs):  # real signature unknown
        pass
