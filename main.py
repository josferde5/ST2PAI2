import random
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

    c = config.Config()
    logger.setLevel(c.logging_level)


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
    p = Process(target=server.tcpip_server, args=(7070,))
    p.start()
    client.tcpip_client(7070,
                        23636500034428764479244706838976857737400240931731689727911481883833885852046528112333064782260329768244802925929644443038425621307027595611695201155498156223753452615667663501337720399386057832133951,
                        2)
