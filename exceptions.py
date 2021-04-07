class ApplicationError(Exception):

    def __init__(self, message):
        self.message = message


class NewFileException(Exception):

    def __init__(self, message):
        self.message = message
