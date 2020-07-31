from .failed_counter import FailedCounter
from .logging import Logging
from .otp_service import OtpService, IOtpService
from .sha_256_adapter import Sha256Adapter, IHash
from .slack_adapter import SlackAdapter
from .user import User, IUser


class AuthenticationService:
    def __init__(self):
        self._user: IUser = User()
        self._hash: IHash = Sha256Adapter()
        self._otp_service: IOtpService = OtpService()
        self._failed_counter: FailedCounter = FailedCounter()
        self._slack_adapter: SlackAdapter = SlackAdapter()
        self._logging: Logging = Logging()

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

            self._slack_adapter.notify(username)

            failed_count = self._failed_counter.get(username)
            self._logging.log_failed_count(f'user: {username} failed times: {failed_count}')

            return False


class FailedTooManyTimesError(OSError):
    def __init__(self, *args, **kwargs):  # real signature unknown
        pass
