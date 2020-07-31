import logging
from abc import ABCMeta, abstractmethod


class ILogging(metaclass=ABCMeta):
    @abstractmethod
    def info(self, message):
        pass


class Logging(ILogging):
    def info(self, message) -> None:
        logging.info(message)
