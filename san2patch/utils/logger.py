import logging
import os
from abc import ABC
from datetime import datetime
from enum import Enum

import coloredlogs


class MyLoggerLevelEnum(Enum):
    CRITICAL = 50
    FATAL = CRITICAL
    SUCCESS = 45  # Added
    ERROR = 40
    WARNING = 30
    WARN = WARNING
    INFO = 20
    DEBUG = 10
    NOTSET = 0


field_styles = {
    "asctime": {"color": "green"},
    "hostname": {"color": "magenta"},
    "levelname": {"color": "cyan", "bold": True},
    "name": {"color": "blue"},
    "message": {"color": "white"},
}

level_styles = {
    "debug": {"color": "white"},
    "info": {"color": "green"},
    "warning": {"color": "yellow"},
    "error": {"color": "red"},
    "success": {"color": "blue", "bold": True},  # Custom level color
    "critical": {"color": "red", "bold": True},
}


class BaseLogger(ABC):
    def __init__(
        self,
        name: str | None = None,
        log_level: int | None = None,
        file_handler: bool = False,
    ):
        if name is None:
            self.name = self.__class__.__qualname__
        else:
            self.name = name

        if log_level is None:
            if os.getenv("LOG_LEVEL") is None:
                log_level = logging.DEBUG
            else:
                try:
                    log_level = MyLoggerLevelEnum[os.getenv("LOG_LEVEL")].value
                except KeyError:
                    log_level = logging.DEBUG

        # Add custom levels
        logging.addLevelName(MyLoggerLevelEnum.SUCCESS.value, "SUCCESS")

        def success(self, message, *args, **kws):
            if self.isEnabledFor(MyLoggerLevelEnum.SUCCESS.value):
                self._log(MyLoggerLevelEnum.SUCCESS.value, message, args, **kws)

        logging.Logger.success = success

        # log setting
        self.logger = logging.getLogger(self.name)

        coloredlogs.install(
            fmt="%(asctime)s [%(name)s] %(levelname)s\t%(message)s",
            level="DEBUG",
            logger=self.logger,
            level_styles=level_styles,
            field_styles=field_styles,
        )

        # Save only the error log to a separate file
        # If logs folder does not exist, create it
        if not os.path.exists("./logs"):
            os.makedirs("./logs")

        # Create a file handler & Add the file handler to the logger
        if file_handler:
            error_file_handler = logging.FileHandler(
                f"./logs/{self.name}_error_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log"
            )
            error_file_handler.setLevel(logging.ERROR)
            self.logger.addHandler(error_file_handler)

        # Set the log level
        self.log_level = log_level
        self.logger.setLevel(self.log_level)
