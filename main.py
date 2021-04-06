import time
import client, reports
import file_server
import os
import shutil
import schedule
import config
from error import ApplicationError
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(levelname)s %(asctime)s - %(message)s', level='INFO')


def initial_store(c):
    for d in c.directories:
        file_server.store_files(d)


def periodical_check():
    logger.info("Periodical check started")
    tic = time.perf_counter()
    c = config.Config()
    file_server.register_analysis_time()
    entries = []
    for d in c.directories:
        for root, dirs, filenames in os.walk(d):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                filepath, file_hash_server, verification_hash, failed_reason = client.check_file_integrity(full_path)
                entries.append(
                    [datetime.now().strftime('%d/%m/%Y %H:%M:%S'), filepath, file_hash_server, verification_hash, failed_reason])

    files_deleted = file_server.check_deleted_files()
    reports.create_logs(tuple(entries), files_deleted)
    tac = time.perf_counter()
    logger.info("Periodical check finished")
    logger.debug(f"Time elapsed: {tac-tic:0.4f} seconds")


def configuration():
    if not os.path.exists('config.ini'):
        logger.error("There's no configuration file in the root folder of the project")
        raise ApplicationError("There's no configuration file in the root folder of the project")

    # Lectura del archivo de configuración
    c = config.Config()
    logger.setLevel(c.logging_level)

    if os.path.exists('Reports'):
        shutil.rmtree('Reports')
    os.mkdir('Reports')

    # Populación inicial del sistema de archivos
    initial_store(c)

    # Programación de tareas:
    if c.check_periodicity != 0 and c.report_generation_periodicity != 0:
        schedule.every(c.check_periodicity).minutes.do(periodical_check)
        schedule.every(c.report_generation_periodicity).minutes.do(reports.create_report)
    else:
        schedule.every().day.at("00:00").do(periodical_check)
        schedule.every().day.at("08:00").do(reports.create_report)


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

    while True:
        schedule.run_pending()
        time.sleep(1)
