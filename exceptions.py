class ApplicationError(Exception):

    def __init__(self, message):
        self.message = message


class DiffieHellmanError(Exception):

    def __init__(self, message):
        self.message = message
