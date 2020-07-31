import logging
from abc import ABCMeta, abstractmethod


class ILogging(metaclass=ABCMeta):
    @abstractmethod
    def log_failed_count(self, message):
        pass


class Logging(ILogging):
    def log_failed_count(self, message) -> None:
        logging.info(message)
