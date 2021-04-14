import socket
import random

buffer_size = 16384

msgs = []


def tcp_ip_adversary(port, server_port):
    adv_socket_receive = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    adv_socket_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    with adv_socket_send:
        adv_socket_send.connect(('localhost', server_port))
        with adv_socket_receive:
            adv_socket_receive.bind(('localhost', port))
            adv_socket_receive.listen(1)
            connection_client, client_address = adv_socket_receive.accept()
            with connection_client:
                stop = False
                while not stop:
                    while not stop:
                        data = connection_client.recv(buffer_size)
                        if not data:
                            continue
                        received_info = str(data, 'utf-8')
                        decoded = received_info.split(',')
                        decoded_first_part = decoded[0].split()
                        mutate = random.randint(0, 2)
                        if received_info.startswith("END"):
                            adv_socket_send.sendall(bytes("END", 'utf-8'))
                            stop = True
                            break
                        elif len(decoded_first_part) == 3 and mutate == 1:
                            int_to_modify = random.randint(0, 2)
                            decoded_first_part[int_to_modify] = str(int(decoded_first_part[int_to_modify]) + 200)
                            decoded[0] = " ".join(decoded_first_part)
                            str_to_send = ",".join(decoded)
                            adv_socket_send.sendall(bytes(str_to_send, 'utf-8'))
                            break
                        elif len(decoded_first_part) == 3 and mutate == 2 and len(msgs) > 0:
                            str_to_send = msgs[random.randint(0, len(msgs) - 1)]
                            adv_socket_send.sendall(bytes(str_to_send, 'utf-8'))
                            break
                        else:
                            adv_socket_send.sendall(data)
                            if len(decoded_first_part) == 3:
                                msgs.append(received_info)
                            if len(decoded) != 2:
                                break

                    while not stop:
                        data = adv_socket_send.recv(buffer_size)
                        if not data:
                            continue
                        else:
                            connection_client.sendall(data)
                            break
