from app import AuthenticationService, INotification, ILogging, IOtpService, IFailedCounter, IHash, IUser
from app.failed_counter_decorator import FailedCounterDecorator
from app.logging_decorator import LoggingDecorator
from app.notification_decorator import NotificationDecorator


class FakeSlack(INotification):
    def notify(self, username: str) -> None:
        print(f'fake_slack.notify - Notify user: {username}')


class FakeLogging(ILogging):
    def info(self, message):
        print(f'fake_logging.info - Log message : {message}')


class FakeOtp(IOtpService):
    def get_current_otp(self, username: str) -> str:
        print(f'fake_otp.get_current_otp - Get otp of user: {username}')
        return "current_otp"


class FakeFailedCounter(IFailedCounter):
    def reset(self, username: str) -> None:
        print(f'fake_failed_counter.reset - Reset failed count of user: {username}')

    def add(self, username: str) -> None:
        print(f'fake_failed_counter.add - Add failed count of user: {username}')

    def get(self, username: str) -> int:
        print(f'fake_failed_counter.get - Get failed count of user: {username}')
        return 100

    def is_account_locked(self, username: str) -> bool:
        print(f'fake_failed_counter.is_account_locked - Check is account locked of user: {username}')
        return False


class FakeHash(IHash):
    def compute(self, password: str) -> str:
        print(f'fake_hash.compuate - Compute hashed password from password: {password}')
        return "hashed_password"


class FakeUser(IUser):
    def get_password(self, username: str) -> str:
        print(f'fake_user.get_password - Get hashed password from user: {username}')
        return "hashed_password"


if __name__ == '__main__':
    notification = FakeSlack()
    logging = FakeLogging()
    failed_counter = FakeFailedCounter()
    otp_service = FakeOtp()
    hash = FakeHash()
    user = FakeUser()
    authentication_service = AuthenticationService(user, hash, otp_service)
    authentication_service = NotificationDecorator(authentication_service, notification)
    authentication_service = FailedCounterDecorator(authentication_service, failed_counter)
    authentication_service = LoggingDecorator(authentication_service, logging, failed_counter)
    authentication_service.verify("sharefun", "123456", "current_otp")
    exit(0)
