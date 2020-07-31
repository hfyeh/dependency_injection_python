import os

from .sha_256_adapter import Sha256Adapter
from .user import User
import requests
from slack import WebClient
from slack.errors import SlackApiError
import logging


class AuthenticationService:
    def __init__(self):
        self._user: User = User()
        self._sha_256_adapter: Sha256Adapter = Sha256Adapter()

    def verify(self, username: str, password: str, otp: str) -> bool:
        if self.is_account_locked(username):
            raise FailedTooManyTimesError()

        password_from_db = self._user.get_password_from_db(username)

        hashed_password = self._sha_256_adapter.compute_hashed_password(password)

        current_otp = self.get_current_otp(username)

        if password_from_db == hashed_password and otp == current_otp:
            self.reset_failed_count(username)

            return True
        else:
            self.add_failed_count(username)

            self.notify(username)

            self.log_failed_count(username)

            return False

    def is_account_locked(self, username: str) -> bool:
        response = requests.post('https://sharefun.com/api/is_locked', data={username: username})
        response.raise_for_status()
        is_acount_locked = response.json()['is_account_locked']
        return is_acount_locked

    def log_failed_count(self, username: str) -> None:
        failed_count = self.get_failed_count(username)
        logging.info(f'user: {username} failed times: {failed_count}')

    def get_failed_count(self, username: str) -> int:
        response = requests.post('https://sharefun.com/api/get_failed_count', data={username: username})
        response.raise_for_status()
        failed_count = response.json()['failed_count']
        return failed_count

    def notify(self, username: str) -> None:
        try:
            slack_client = WebClient(token=os.environ['SLACK_API_TOKEN'])
            response = slack_client.chat_postMessage(channel='#channel', text=f'{username} failed to login')
        except SlackApiError as e:
            assert e.response['ok'] is False

    def add_failed_count(self, username: str) -> None:
        response = requests.post('https://sharefun.com/api/failed_counter/add', data={username: username})
        response.raise_for_status()

    def reset_failed_count(self, username: str) -> None:
        response = requests.post('https://sharefun.com/api/failed_counter/reset', data={username: username})
        response.raise_for_status()

    def get_current_otp(self, username: str) -> str:
        response = requests.post('https://sharefun.com/api/otp', data={username: username})
        if not (response.status_code == requests.codes.ok):
            raise PermissionError()
        current_otp = response.json()['otp']
        return current_otp


class FailedTooManyTimesError(OSError):
    def __init__(self, *args, **kwargs):  # real signature unknown
        pass
