import hashlib
import hmac
import secrets
import socket
import random
import errno
import client
import database
from exceptions import DiffieHellmanError
import logging
import config

logger = logging.getLogger(__name__)
_hash_algorithm = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
    "SHA3_256": hashlib.sha3_256,
    "SHA3_512": hashlib.sha3_512,
    "BLAKE2B": hashlib.blake2b,
    "BLAKE2S": hashlib.blake2s
}
buffer_size = 16384


def generate_nonce():
    return secrets.token_hex(64)


def challenge(key, nonce):
    key_int = int(key, base=16)
    nonce_int = int(nonce, base=16)
    if nonce_int > key_int:
        return nonce_int % key_int
    else:
        return key_int % nonce_int


def message_hmac(message, key, nonce):
    c = config.Config()
    msg_bytes = bytes(message, encoding='UTF-8')
    challenge_bytes = challenge(key, nonce).to_bytes(200, byteorder="big")
    digester = hmac.new(challenge_bytes, msg_bytes, _hash_algorithm.get(c.hashing_algorithm, hashlib.blake2s))
    return digester.hexdigest()


def key_agreement(server_socket, received_info):
    data = received_info.split(',')
    w = random.randint(1, int(data[1]) - 1)
    dh = pow(int(data[3]), w, int(data[1]))
    b = pow(int(data[2]), w, int(data[1]))
    nonce = generate_nonce()
    mac_b = message_hmac(data[3], str(dh), nonce)
    server_socket.sendall(bytes(f'{str(b)},{str(mac_b)},{nonce}', 'utf-8'))

    try:
        data = server_socket.recv(buffer_size)
        received_info = str(data, 'utf-8').split(',')
    except socket.error as e:
        if e.errno == errno.ECONNABORTED:
            print("SERVER INFO: Connection aborted by the client. Maybe a problem with Diffie-Hellman key agreement?")
            return None

    mac_a = message_hmac(str(b), str(dh), received_info[1])
    if not mac_a == received_info[0] or database.exists_nonce(received_info[1]):
        print(
            "SERVER INFO: the MAC received does not match with the one obtained in the server or NONCE wasn't unique. Aborting connection.")
        raise DiffieHellmanError(
            'The MAC received does not match with the one obtained in the or NONCE was not unique.')
    else:
        database.insert_nonce(received_info[1])
        key_hex = format(dh, 'x')
        print(f"SERVER INFO: the key is {key_hex}")
        return key_hex


def tcpip_server(s_socket):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with server_socket:
        server_addr = ('localhost', s_socket)
        server_socket.bind(server_addr)
        server_socket.listen(1)
        print('SERVER INFO: Server up, waiting for a connection.')
        connection, client_address = server_socket.accept()
        print('SERVER INFO: received connection from', client_address)
        with connection:
            while True:
                data = connection.recv(buffer_size)
                if not data:
                    continue

                received_info = str(data, 'utf-8')
                decoded = received_info.split(',')
                if decoded[0] == 'END':
                    break
                elif decoded[0] == 'KEYAGREEMENT':
                    print(f"SERVER INFO: establishing key agreement with Diffie-Hellman")
                    try:
                        key = key_agreement(connection, received_info)
                        if not key:
                            break
                    except DiffieHellmanError:
                        break
                else:
                    print("SERVER INFO: Received from client the following message: " + decoded[0])
                    result = verify_integrity(decoded[0], decoded[1], key, decoded[2], 'CLIENT', 'SERVER')   
                    connection.send(bytes(result, 'utf-8')) 

            print("SERVER INFO: Closing server.")


def update_logs(message, hmac_emisor, nonce, key, fail, emisor):
    dirname = os.path.dirname(__file__)
    filename = 'logs.xlsx'
    pathname = os.path.join(dirname, filename)

    if os.path.exists(pathname):
        workbook = openpyxl.load_workbook(filename)
        worksheet = workbook['Logs']
        thin_border = Border(left=Side(style='thin'), 
                     right=Side(style='thin'), 
                     top=Side(style='thin'), 
                     bottom=Side(style='thin'))
        max_row = worksheet.max_row

        worksheet.cell(row=max_row+1, column=2).value = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        worksheet.cell(row=max_row+1, column=2).border = thin_border
        worksheet.cell(row=max_row+1, column=3).value = message
        worksheet.cell(row=max_row+1, column=3).border = thin_border
        worksheet.cell(row=max_row+1, column=4).value = hmac_emisor
        worksheet.cell(row=max_row+1, column=4).border = thin_border
        worksheet.cell(row=max_row+1, column=5).value = nonce
        worksheet.cell(row=max_row+1, column=5).border = thin_border
        worksheet.cell(row=max_row+1, column=6).value = key
        worksheet.cell(row=max_row+1, column=6).border = thin_border
        worksheet.cell(row=max_row+1, column=7).value = fail
        worksheet.cell(row=max_row+1, column=7).border = thin_border
        worksheet.cell(row=max_row+1, column=8).value = emisor
        worksheet.cell(row=max_row+1, column=8).border = thin_border

        workbook.save(filename)

    else:
        workbook = xlsxwriter.Workbook(pathname)
        worksheet = workbook.add_worksheet('Logs')

        title_format = workbook.add_format({'bold': 1, 'align': 'center', 'valign': 'vcenter', 'border': 1, 'border_color': '#000000'})
        column_title_format = workbook.add_format({'align': 'center', 'valign': 'vcenter', 'border': 1, 'border_color': '#000000'})
        data_format = workbook.add_format({'valign': 'vcenter', 'border': 1, 'border_color': '#000000'})

        worksheet.set_column(1, 7, 24)

        worksheet.merge_range("B2:G2", 'Transmission integrity logs', title_format)
        worksheet.write(2, 1, 'Datetime', column_title_format)
        worksheet.write(3, 1, datetime.now().strftime("%d/%m/%Y %H:%M:%S"), data_format)

        worksheet.write(2, 2, 'Message', column_title_format)
        worksheet.write(3, 2, message, data_format)

        worksheet.write(2, 3, 'HMAC', column_title_format)
        worksheet.write(3, 3, hmac, data_format)

        worksheet.write(2, 4, 'Nonce', column_title_format)
        worksheet.write(3, 4, nonce, data_format)

        worksheet.write(2, 5, 'Key', column_title_format)
        worksheet.write(3, 5, key, data_format)

        worksheet.write(2, 6, 'Integrity fail', column_title_format)
        worksheet.write(3, 6, fail, data_format)

        worksheet.write(2, 7, 'Emisor', column_title_format)
        worksheet.write(3, 7, emisor, data_format)

        workbook.close()
        
    print('SERVER INFO: Logs were updated')


def verify_integrity(message, hmac_emisor, key, nonce, emisor, receiver):
    if hmac_emisor == message_hmac(message, key, nonce) and not database.exists_nonce(nonce):
        database.insert_nonce(nonce)
        result = 'The integrity of the message transmission has been verified correctly.'
        print(receiver + ' INFO: ' +  result)

    elif hmac_emisor == message_hmac(message, key, nonce) and database.exists_nonce(nonce):
        update_logs(message, hmac_emisor, nonce, key, 'Duplicate nonce', emisor)
        result = 'A reply attack has been detected. The nonce used is duplicated.'
        print(receiver + ' WARN: ' +  result)

    else: 
        update_logs(message, hmac_emisor, nonce, key, 'Modified message content', emisor)
        result = 'A MiDM attack has been detected. Integrity void, message modified or treated.'
        print(receiver + ' WARN: ' +  result)
    
    return result