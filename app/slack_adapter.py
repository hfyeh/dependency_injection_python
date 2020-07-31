import os
from abc import ABCMeta, abstractmethod

from slack import WebClient
from slack.errors import SlackApiError


class INotification(metaclass=ABCMeta):
    @abstractmethod
    def notify(self, username: str) -> None:
        pass


class SlackAdapter(INotification):
    def notify(self, username: str) -> None:
        try:
            slack_client = WebClient(token=os.environ['SLACK_API_TOKEN'])
            response = slack_client.chat_postMessage(channel='#channel', text=f'{username} failed to login')
        except SlackApiError as e:
            assert e.response['ok'] is False
