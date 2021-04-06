from configparser import ConfigParser
import logging
import re

_log_level = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "NOTSET": logging.NOTSET
}


class ConfigSingleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(ConfigSingleton, cls).__call__(*args, **kwargs)

            config = ConfigParser()
            config.read('config.ini')

            c = config['CONFIG']

            cls.logging_format = c.get('loggingFormat', '%(levelname)s %(asctime)s: %(message)s', raw=True)
            cls.logging_level = _log_level.get(c.get('loggingLevel', 'INFO'), logging.INFO)

            logging.basicConfig(format=cls.logging_format, level=cls.logging_level)
            logger = logging.getLogger(__name__)

            cls.directories = c.get('dirsToCheck', None)
            if cls.directories is None or cls.directories == '':
                logger.error("'dirsToCheck' parameter was not set in config.ini, and it is mandatory")
                input('Press Enter to stop the execution')
                exit(1)
            cls.directories = cls.directories.split(',')

            cls.contact_email = c.get('contactEmail', None)
            if cls.contact_email is None or not re.match(r"[^@]+@[^@]+\.[^@]+", cls.contact_email):
                logger.error("'email' parameter was not set in config.ini or is not valid")
                input('Press Enter to stop the execution')
                exit(1)

            cls.check_periodicity = float(c.get('checkPeriodicity', '0'))
            cls.report_generation_periodicity = float(c.get('reportGenerationPeriodicity', '0'))

            cls.hashing_algorithm = c.get('hashingAlgorithm', 'BLAKE2S')

            if cls.hashing_algorithm not in ('SHA1', 'SHA256', 'SHA512', 'SHA3_256', 'SHA3_512', 'BLAKE2S', 'BLAKE2B'):
                logger.warning(
                    "You set an invalid hashing algorithm. Possible values are: SHA1, SHA256, SHA512, SHA3_256, SHA3_512, BLAKE2B, BLAKE2S")
                logger.warning("Using BLAKE2S as default")


        return cls._instances[cls]


class Config(metaclass=ConfigSingleton):
    pass
