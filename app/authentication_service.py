import os
from .user import User
import hashlib
import requests
from slack import WebClient
from slack.errors import SlackApiError


class AuthenticationService:
    def verify(self, username: str, password: str, otp: str) -> bool:
        password_from_db = User.query.filter_by(username=username).first().password

        crypt = hashlib.sha256()
        crypt.update(password)
        hash = crypt.hexdigest()
        hashed_password = hash

        response = requests.post('https://sharefun.com/api/otp', data={username: username})
        if response.status_code == requests.codes.ok:
            otp1 = response.json()['otp']
        else:
            raise PermissionError()
        current_otp = otp1

        if password_from_db == hashed_password and otp == current_otp:
            return True
        else:
            try:
                slack_client = WebClient(token=os.environ['SLACK_API_TOKEN'])
                response = slack_client.chat_postMessage(channel='#channel', text=f'{username} failed to login')
            except SlackApiError as e:
                assert e.response['ok'] is False

            return False
