import adversary
import client
import database
import server
import os
import config
from multiprocessing import Process
import logging

from exceptions import ApplicationError

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(levelname)s %(asctime)s - %(message)s', level='INFO')


def configuration():
    if not os.path.exists('config.ini'):
        logger.error("There's no configuration file in the root folder of the project")
        raise ApplicationError("There's no configuration file in the root folder of the project")

    database.init_database()


if __name__ == "__main__":
    print("#############################################")
    print("#    _     _ _ ______  ______ ______ _ _    #")
    print("#   (_)   (_) (______)/ _____) _____) | |   #")
    print("#    _______| |_     ( (____( (____ | | |   #")
    print("#   |  ___  | | |   | \____ \\\\____ \| | |   #")
    print("#   | |   | | | |__/ /_____) )____) ) | |   #")
    print("#   |_|   |_|_|_____/(______(______/|_|_|   #")
    print("#                                           #")
    print("#############################################")

    configuration()
    c = config.Config()
    p1 = Process(target=adversary.tcp_ip_adversary, args=(c.port + 1, c.port))
    p2 = Process(target=server.tcpip_server, args=(c.port,))
    p1.start()
    p2.start()
    client.tcpip_client(c.port + 1)
