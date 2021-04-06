import csv, os
import pandas as pd
from datetime import datetime
import logging
import xlsxwriter
import shutil
import time
import config

import email_module

logger = logging.getLogger(__name__)


def update_stats(rows, files_deleted):
    dirname = os.path.dirname(__file__)
    stats_filename = os.path.join(dirname, 'Reports/stats.csv')
    failed_checks_filename = os.path.join(dirname, 'Reports/failed_checks.csv')
    total_checks = 0
    checks_passed = 0
    checks_failed_hash = 0
    checks_failed_mac = 0
    files_added = 0
    not_found_deleted = len(files_deleted)
    failed_files = []

    for row in rows:
        total_checks += 1
        if row[3] is None:
            files_added += 1
        elif row[3]:
            checks_passed += 1
        elif row[4] == 'hash':
            checks_failed_hash += 1
            failed_files.append([row[0], row[1], row[4]])
        else:
            checks_failed_mac += 1
            failed_files.append([row[0], row[1], row[4]])

    for df in files_deleted:
        failed_files.append([datetime.now().strftime("%m/%d/%Y %H:%M:%S"), df, 'deleted'])

    if os.path.isfile(stats_filename):
        with open(stats_filename, 'r', newline='') as file:
            reader = csv.reader(file, delimiter='|', quotechar="'", quoting=csv.QUOTE_NONNUMERIC)
            next(reader)
            line = next(reader)
            total_checks += line[0]
            checks_passed += line[1]
            checks_failed_hash += line[2]
            checks_failed_mac += line[3]
            not_found_deleted += line[4]
            files_added += line[5]

    with open(stats_filename, 'w', newline='') as file:
        writer = csv.writer(file, delimiter='|', quotechar="'", quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(['TOTAL_CHECKS', 'CHECKS_PASSED', 'CHECKS_FAILED_HASH', 'CHECKS_FAILED_MAC', 'NOT_FOUND_DELETED', 'NUMBER_FILES_ADDED'])
        writer.writerow([total_checks, checks_passed, checks_failed_hash, checks_failed_mac, not_found_deleted, files_added])

    if os.path.isfile(failed_checks_filename):
        with open(failed_checks_filename, 'a', newline='') as file:
            writer = csv.writer(file, delimiter='|', quotechar="'", quoting=csv.QUOTE_NONNUMERIC)
            writer.writerows(failed_files)
    else:
        with open(failed_checks_filename, 'w', newline='') as file:
            writer = csv.writer(file, delimiter='|', quotechar="'", quoting=csv.QUOTE_NONNUMERIC)
            writer.writerow(['DATETIME', 'FILENAME', 'FAIL_REASON'])
            writer.writerows(failed_files)

    logger.info("The stats.csv and failed_checks.csv files have been updated")

    if len(failed_files) > 0:
        email_module.send_alert_email(failed_files)


def create_logs(rows, files_deleted):
    dirname = os.path.dirname(__file__)
    dt = datetime.now().strftime("%d%m%Y%H%M%S")
    filename = os.path.join(dirname, 'Reports/log-%s.csv' % dt)
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file, delimiter='|', quotechar="'", quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(['DATE', 'FILE_PATH', 'HASH_FILE', 'INTEGRITY_VERIFICATION'])
        writer.writerows(rows)
    logger.info('The %s file has been created. %d entries have been added.', filename, len(rows))

    update_stats(rows, files_deleted)


def create_report():
    c = config.Config()
    if c.report_generation_periodicity is not None or datetime.day == 1:
        dirname = os.path.dirname(__file__)
        now = datetime.now()

        filename = 'report.xlsx'
        pathname = os.path.join(dirname, 'Reports/' + filename)

        if os.path.exists(pathname):
            os.remove(pathname)

        workbook = xlsxwriter.Workbook(pathname)
        worksheet = workbook.add_worksheet()

        stats = pd.read_csv('Reports/stats.csv', sep='|', quotechar="'", quoting=csv.QUOTE_NONNUMERIC)
        failed_checks = pd.read_csv('Reports/failed_checks.csv', sep='|', quotechar="'", quoting=csv.QUOTE_NONNUMERIC)

        title_format = workbook.add_format({'bold': 1, 'align': 'center', 'valign': 'vcenter', 'border': 1, 'border_color': '#000000'})
        column_title_format = workbook.add_format({'align': 'center', 'valign': 'vcenter', 'border': 1, 'border_color': '#000000'})
        data_format = workbook.add_format({'valign': 'vcenter', 'border': 1, 'border_color': '#000000'})

        worksheet.set_column(1, 7, 23.57)

        worksheet.merge_range("B2:H2", 'HIDS Report', title_format)
        worksheet.merge_range("B3:H3", 'Generation date: %s' % now.strftime("%d/%m/%Y %H:%M:%S"), column_title_format)
        worksheet.write(3, 1, 'Total checks', column_title_format)
        worksheet.write(4, 1, int(stats['TOTAL_CHECKS'][0]), data_format)

        worksheet.write(3, 2, 'Checks passed', column_title_format)
        worksheet.write(4, 2, int(stats['CHECKS_PASSED'][0]), data_format)

        worksheet.write(3, 3, 'Checks failed by hash', column_title_format)
        worksheet.write(4, 3, int(stats['CHECKS_FAILED_HASH'][0]), data_format)

        worksheet.write(3, 4, 'Checks failed by MAC', column_title_format)
        worksheet.write(4, 4, int(stats['CHECKS_FAILED_MAC'][0]), data_format)

        percentage_format = workbook.add_format({'num_format': '0.0000%', 'valign': 'vcenter', 'border': 1, 'border_color': '#000000'})
        worksheet.write(3, 5, 'Integrity rate', column_title_format)
        worksheet.write_formula(4, 5, '=C5/B5', cell_format=percentage_format)

        worksheet.write(3, 6, 'Not found or deleted files', column_title_format)
        worksheet.write(4, 6, int(stats['NOT_FOUND_DELETED'][0]), data_format)

        worksheet.write(3, 7, 'Number of files added', column_title_format)
        worksheet.write(4, 7, int(stats['NUMBER_FILES_ADDED'][0]), data_format)

        worksheet.merge_range("B7:E7", 'Checks failed', title_format)
        worksheet.write(7, 1, 'Datetime', column_title_format)
        worksheet.merge_range('C8:D8', 'Filename', column_title_format)
        worksheet.write(7, 4, 'Fail reason', column_title_format)
        row = 8
        for i, data in failed_checks.iterrows():
            worksheet.write(row, 1, data['DATETIME'], data_format)
            worksheet.merge_range('C' + str(row+1) + ':D' + str(row+1), data['FILENAME'], data_format)
            worksheet.write(row, 4, data['FAIL_REASON'], data_format)
            row += 1

        workbook.close()
        email_module.send_report_email(pathname)

        logger.info("The report was created in the 'Reports' folder and the email was sent")

        shutil.move(pathname, filename)
        tic = time.perf_counter()
        while True:
            try:
                shutil.rmtree('Reports')
                break
            except OSError:
                if time.perf_counter() - tic > 30:
                    raise

        os.mkdir('Reports')
        shutil.move(filename, 'Reports/' + filename)
