import os
from .user import User
import hashlib
import requests
from slack import WebClient
from slack.errors import SlackApiError
import logging


class AuthenticationService:
    def verify(self, username: str, password: str, otp: str) -> bool:
        response = requests.post('https://sharefun.com/api/is_locked', data={username: username})
        response.raise_for_status()

        is_acount_locked = response.json()['is_account_locked']
        if is_acount_locked:
            raise FailedTooManyTimesError()

        password_from_db = User.query.filter_by(username=username).first().password

        crypt = hashlib.sha256()
        crypt.update(password)
        hash = crypt.hexdigest()
        hashed_password = hash

        response = requests.post('https://sharefun.com/api/otp', data={username: username})
        if not (response.status_code == requests.codes.ok):
            raise PermissionError()
        current_otp = response.json()['otp']

        if password_from_db == hashed_password and otp == current_otp:
            response = requests.post('https://sharefun.com/api/failed_counter/reset', data={username: username})
            response.raise_for_status()

            return True
        else:
            response = requests.post('https://sharefun.com/api/failed_counter/add', data={username: username})
            response.raise_for_status()

            try:
                slack_client = WebClient(token=os.environ['SLACK_API_TOKEN'])
                response = slack_client.chat_postMessage(channel='#channel', text=f'{username} failed to login')
            except SlackApiError as e:
                assert e.response['ok'] is False

            response = requests.post('https://sharefun.com/api/get_failed_count', data={username: username})
            response.raise_for_status()
            failed_count = response.json()['failed_count']
            logging.info(f'user: {username} failed times: {failed_count}')

            return False


class FailedTooManyTimesError(OSError):
    def __init__(self, *args, **kwargs):  # real signature unknown
        pass
