from app import AuthenticationService, INotification, ILogging, IOtpService, IFailedCounter, IHash, IUser
from app.failed_counter_decorator import FailedCounterDecorator
from app.logging_decorator import LoggingDecorator
from app.notification_decorator import NotificationDecorator

import dependency_injector.providers as providers


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


class Containers:
    """ IoC container """
    user = providers.Factory(FakeUser)
    hash = providers.Factory(FakeHash)
    otp = providers.Factory(FakeOtp)
    authentication = providers.Factory(AuthenticationService, user, hash, otp)

    failed_counter = providers.Factory(FakeFailedCounter)
    notification = providers.Factory(FakeSlack)
    logging = providers.Factory(FakeLogging)

    authentication = providers.Factory(NotificationDecorator, authentication, notification)
    authentication = providers.Factory(FailedCounterDecorator, authentication, failed_counter)
    authentication = providers.Factory(LoggingDecorator, authentication, logging, failed_counter)


if __name__ == '__main__':
    authentication_service = Containers.authentication()
    authentication_service.verify("sharefun", "123456", "current_otp")
    exit(0)
