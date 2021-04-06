from __future__ import print_function

import base64
import datetime
import os.path
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from googleapiclient import errors
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

import config

import logging

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
logger = logging.getLogger(__name__)


def init_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)

    return service


def create_message(sender, to, subject, message_text):
    message = MIMEText(message_text)
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    encoded_msg = base64.urlsafe_b64encode(message.as_bytes())
    return {'raw': encoded_msg.decode()}


def create_file_message(sender, to, subject, message_text, file):
    message = MIMEMultipart()
    message['to'] = to
    message['from'] = sender
    message['subject'] = subject

    msg = MIMEText(message_text)
    message.attach(msg)

    part = MIMEBase('application', "vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    part.set_payload(open(file, "rb").read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment', filename="hids-report.xlsx")
    message.attach(part)

    encoded_msg = base64.urlsafe_b64encode(message.as_bytes())
    return {'raw': encoded_msg.decode()}


def send_message(service, user_id, message):
    try:
        message = (service.users().messages().send(userId=user_id, body=message)
                   .execute())
        logger.info('Message Sent with Id: %s', message['id'])
        return message
    except errors.HttpError as error:
        logger.exception('An error occurred', error)


def send_alert_email(files_failed):
    c = config.Config()
    dt_string = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    email_sender = 'HIDS ST2 Service'
    email_to = c.contact_email
    email_subject = 'ALERTA: Detectado fallo de integridad'

    email_body = 'Durante la verificación del sistema de archivos en vigilancia con fecha y hora ' + dt_string + ', se han detectado fallos de integridad en los siguientes ficheros:\n'

    for dt, filename, reason in files_failed:
        if reason == 'hash':
            email_body += ' - El fichero ' + filename + ' presenta un fallo de integridad ya que el hash enviado por el cliente no es igual al almacenado en el servidor.\n'
        elif reason == 'mac':
            email_body += ' - El fichero ' + filename + ' presenta un fallo de integridad ya que el MAC obtenido en el cliente no es igual al obtenido en el servidor.\n'
        else:
            email_body += ' - El fichero ' + filename + ' presenta un fallo de integridad ya que ha sido eliminado o no se encuentra.\n'

    raw_message = create_message(email_sender, email_to, email_subject, email_body)
    send_message(init_service(), "me", raw_message)


def send_report_email(report_path):
    c = config.Config()
    email_sender = 'HIDS ST2 Service'
    email_to = c.contact_email
    email_subject = 'INFORMACIÓN: Informe de integridad mensual'
    email_body = 'A través de este email se pone a su disposición un reporte de las verificaciones de integridad del sistema de archivos del último mes. A partir de este momento se cierra el ciclo de verificación y se comienza el siguiente. Podrá encontrar el reporte en los archivos adjuntos de este email.'

    raw_message = create_file_message(email_sender, email_to, email_subject, email_body, report_path)
    send_message(init_service(), "me", raw_message)
