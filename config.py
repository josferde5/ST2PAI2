from configparser import ConfigParser
import os


class ConfigSingleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(ConfigSingleton, cls).__call__(*args, **kwargs)

            config = ConfigParser()
            config.read('config.ini')

            c = config['CONFIG']

            cls.prime = c.get('primeNumber', None)
            if cls.prime is None or cls.prime == '':
                print("ERROR: 'primeNumber' parameter was not set in config.ini, and it is mandatory")
                input('Press Enter to stop the execution')
                exit(1)
            cls.prime = int(cls.prime)

            cls.generator = c.get('generator', None)
            if cls.generator is None or cls.generator == '':
                print("ERROR: 'generator' parameter was not set in config.ini or is not valid")
                input('Press Enter to stop the execution')
                exit(1)
            cls.generator = int(cls.generator)

            cls.hashing_algorithm = c.get('hashingAlgorithm', 'BLAKE2S')

            if cls.hashing_algorithm not in ('SHA1', 'SHA256', 'SHA512', 'SHA3_256', 'SHA3_512', 'BLAKE2S', 'BLAKE2B'):
                print(
                    "WARNING: You set an invalid hashing algorithm. Possible values are: SHA1, SHA256, SHA512, SHA3_256, SHA3_512, BLAKE2B, BLAKE2S")
                print("INFO: Using BLAKE2S as default")

            cls.port = c.get('port', '7070')
            if cls.port == '':
                cls.port = '7070'
            cls.port = int(cls.port)

            if os.path.exists("logs.xlsx"):
                os.remove("logs.xlsx")

        return cls._instances[cls]


class Config(metaclass=ConfigSingleton):
    pass
