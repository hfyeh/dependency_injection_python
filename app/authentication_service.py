from .failed_counter import FailedCounter
from .logging import Logging
from .otp_service import OtpService
from .sha_256_adapter import Sha256Adapter
from .slack_adapter import SlackAdapter
from .user import User


class AuthenticationService:
    def __init__(self):
        self._user: User = User()
        self._sha_256_adapter: Sha256Adapter = Sha256Adapter()
        self._otp_service: OtpService = OtpService()
        self._failed_counter: FailedCounter = FailedCounter()
        self._slack_adapter: SlackAdapter = SlackAdapter()
        self._logging: Logging = Logging()

    def verify(self, username: str, password: str, otp: str) -> bool:
        if self._failed_counter.is_account_locked(username):
            raise FailedTooManyTimesError()

        password_from_db = self._user.get_password_from_db(username)

        hashed_password = self._sha_256_adapter.compute_hashed_password(password)

        current_otp = self._otp_service.get_current_otp(username)

        if password_from_db == hashed_password and otp == current_otp:
            self._failed_counter.reset_failed_count(username)

            return True
        else:
            self._failed_counter.add_failed_count(username)

            self._slack_adapter.notify(username)

            failed_count = self._failed_counter.get_failed_count(username)
            self._logging.log_failed_count(f'user: {username} failed times: {failed_count}')

            return False


class FailedTooManyTimesError(OSError):
    def __init__(self, *args, **kwargs):  # real signature unknown
        pass
