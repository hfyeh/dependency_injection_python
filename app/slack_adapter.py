import os

from slack import WebClient
from slack.errors import SlackApiError


class SlackAdapter:
    def notify(self, username: str) -> None:
        try:
            slack_client = WebClient(token=os.environ['SLACK_API_TOKEN'])
            response = slack_client.chat_postMessage(channel='#channel', text=f'{username} failed to login')
        except SlackApiError as e:
            assert e.response['ok'] is False