import signal
import socket
import struct
import hashlib
import selectors

# Hard code location of the server.  Not what we'll want to be doing in the assignment,
# but okay for an example like this.
import sys

UDP_IP = "localhost"
UDP_PORT = 0

# Define a maximum string size for the text we'll be receiving.
MAX_STRING_SIZE = 256

# the format is {username: [addr, [followlist]]}
client_list = {}

file_data = []
# Our main function.

sel = selectors.DefaultSelector()
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind((UDP_IP, UDP_PORT))
count, check_seq = 0, 0


# Function to detect empty server
def emptyServer():
    if len(client_list) == 0:
        return True
    else:
        return False


# Function to remove user
def client_remove(user):
    for client in client_list:
        if client == user:
            del client_list[client]
            break


# Function to add follow words
def addFollow(user, items):
    if items in client_list[user][1]:
        return False
    else:
        client_list[user][1].append(items)
        return True


# Function to unfollow items
def unFollow(user, items):
    follow_list = client_list[user][1]
    if items not in follow_list:
        return False
    elif items == "@all" or items == f"@{user}":
        return False
    else:
        follow_list.remove(items)
        return True


# Function to list all the user in current system
def displayUser():
    value = []
    for users in client_list:
        value.append(users)
    my_list = ", ".join(value)
    return my_list


# function to display follow list
def displaylist(x):
    value = ''
    for z in client_list[x][1]:
        value += z + " "

    return value


# Function to check the client in the list
def check_client_in_list(client):
    if client in client_list:
        return True
    return False


# to detect ctrl c terminate
def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')
    message = 'DISCONNECT UDP CHAT/1.0\n'
    for reg in client_list:
        rdt_send_pack(message.encode(), client_list[reg][0])
    sys.exit(0)


# to return a tuple (user, msg)
def format_msg(msg):
    sep = "&MY#SEPARATE&#"
    if msg.startswith("@") and sep in msg:
        line = msg.strip("\n").split(sep, 1)
        user = line[0].strip("@:")
        new_msg = line[1]
        return user, new_msg
    else:
        return False


# Function to detect a follow words in message and return users who have these key words
def detectUserList(messge):
    # print(messge)
    user_list = []
    for users in client_list:
        # compare message and client follow word list have common
        if len(list(set(messge) & set(client_list[users][1]))) >= 1:
            user_list.append(users)
    return user_list


# function to check_
def check_corrupt(received_checksum, compute_checksum):
    if received_checksum == compute_checksum:
        return True
    else:
        return False


# Function to detect command line and processing
def detectCommand(words, user):
    command_msg = 'NO MSG'
    user_addr = client_list[user][0]

    # add items
    if words[0] == "!follow":

        if len(words) < 2:
            command_msg = f"missing the follow item!"
        else:
            if not addFollow(user, words[1]):
                command_msg = f"[{words[1]}] has in {user}'s follow list, cannot add again"
            else:
                command_msg = f"[{words[1]}] add into {user}'s follow list successful"

    # show list
    if words[0] == "!follow?":
        command_msg = ", ".join(displaylist(user).split())

    # unfollow things
    if words[0] == "!unfollow":
        if not unFollow(user, words[1]):
            command_msg = f"[{words[1]}] cannot unfollow from {user}'s follow list"
        else:
            command_msg = f"[{words[1]}] has unfollow from {user}'s follow list successful"

    # show userlist
    if words[0] == "!list":
        command_msg = displayUser()

    # exit the option
    if words[0] == "!exit":
        print('Disconnecting user ' + user)
        command_msg = "DISCONNECT DISCONNECT"
        forwarded_message = f'{command_msg}\n'
        rdt_send_pack(forwarded_message.encode(), user_addr)

        client_remove(user)
        if emptyServer():
            print("No client are in the UDP chatroom, server is disconnecting...exiting!")
            sel.unregister(server_socket)
            server_socket.close()
            sys.exit(0)


    # rest command
    if not command_msg == 'NO MSG':
        forwarded_message = f'{command_msg}\n'
        rdt_send_pack(forwarded_message.encode(), user_addr)


# recv message from client
def rdt_recv_pack(sock, mask):
    global count, check_seq, file_data
    received_packet, addr = sock.recvfrom(1024)

    unpacker = struct.Struct(f'I I 3s {MAX_STRING_SIZE}s 32s')
    UDP_packet = unpacker.unpack(received_packet)

    # Extract out data that was received from the packet.  It unpacks to a tuple,
    # but it's easy enough to split apart.

    received_sequence = UDP_packet[0]
    received_origin = UDP_packet[1]
    received_ack = UDP_packet[2]
    received_data = UDP_packet[3]
    received_checksum = UDP_packet[4]

    # Print out what we received.

    # print("Packet received from:", addr)
    # print("Packet data:", UDP_packet)

    # We now compute the checksum on what was received to compare with the checksum
    # that arrived with the data.  So, we repack our received packet parts into a tuple
    # and compute a checksum against that, just like we did on the sending side.

    values = (received_sequence, received_origin, received_data)
    packer = struct.Struct(f'I I {MAX_STRING_SIZE}s')
    packed_data = packer.pack(*values)
    computed_checksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

    # We can now compare the computed and received checksums to see if any corruption of
    # data can be detected.  Note that we only need to decode the data according to the
    # size we intended to send; the padding can be ignored.

    if check_corrupt(received_checksum, computed_checksum):
        # from keyboard or client message
        if received_origin == 0:
            rdt_send_pack(f"ack{count}".encode(), addr, ack="ACK".encode(), sequence_number=check_seq)
            received_text = received_data[:len(received_data)].decode().rstrip('\x00')
            received_text = received_text.strip("\n")

            # keyboard message
            if format_msg(received_text):
                user, msg = format_msg(received_text)

                # user not in the list first time to visit server
                if not check_client_in_list(user):
                    client_list[user] = [addr, [f"@{user}", "@all"]]
                    data = f"Welcome {user} to The UDP chatroom 1.0"
                    rdt_send_pack(data.encode(), addr)
                    print(f"User {user} has join the UDP chatroom 1.0, Welcome!")

                # user has in the list
                else:
                    # check if it the same port addr
                    # if the port are same then it a same person
                    # if the port are not same, then they are different person

                    # the keyboard message input port only
                    if client_list[user][0] == addr:
                        print(f'Received message from user {user}: {msg}')
                        message = msg.strip('\n')
                        words = message.split()

                        if len(words) >= 1:
                            # To detect command line and processing
                            detectCommand(words, user)

                            # the user who have the key word in the message
                            user_list = detectUserList(words)

                            # To send the msg to the user who has the key word
                            sendMsgWithList(user_list, received_text, user)

                    # same username different port
                    else:
                        data = 'INVALID USERNAME'
                        rdt_send_pack(data.encode(), addr)

            # client message
            else:
                msg = received_text
                if msg.startswith("DISCONNECT"):
                    ending = received_text.split()
                    end_user = ending[1]
                    print('Disconnecting user ' + end_user)
                    client_remove(end_user)

                    if emptyServer():
                        print("No client are in the UDP chatroom, server is disconnecting...exiting!")
                        sel.unregister(server_socket)
                        server_socket.close()
                        sys.exit(0)



            if msg.startswith("ENDOFFILE"):
                words = msg.strip("\n").split(" ", 3)
                filename = words[1]
                client_from = words[2]
                attach_msg = words[3]
                read_file(filename)
                file_data = []
                count = 0
                print(f'{filename} has received from {client_from} successfully')

        # from file
        else:
            # print(f"check_seq: {check_seq}, recv_seq:{received_sequence}")
            # print('Received and computed checksums match, so packet can be processed')

            # print(f'ack was:  {received_ack}')
            # received && not corrupt && seq == 0
            if received_sequence == check_seq:
                print(f"packet received successful #{count}")
                rdt_send_pack(f"ack{count}".encode(), addr ,ack="ACK".encode(), sequence_number=check_seq)
                count += 1
                check_seq = 0
                file_data.append(received_data)

    # seq does not match
    elif check_seq != received_sequence:
        if check_seq == 0:
            check_seq = 1
        else:
            check_seq = 0
        rdt_send_pack(f"ack{count}".encode(), addr ,ack="ACK".encode(), sequence_number=check_seq)

    # received && corrupt
    else:
        if check_seq == 0:
            check_seq = 1
        else:
            check_seq = 0
        print('Received and computed checksums do not match, so packet is corrupt and discarded')
        rdt_send_pack(f"ack{count}".encode(), addr, ack="ACK".encode(), sequence_number=check_seq)

# Function to send meg to user who is in the given list
def sendMsgWithList(user_list, message, user):
    if len(user_list) >= 1:
        for reg in user_list:
            if reg == user:
                continue
            else:
                client_addr = client_list[reg][0]
                forwarded_message = f'{message}\n'
                rdt_send_pack(forwarded_message.encode(), client_addr)

# data is byte type
def rdt_send_pack(data, client_addrs, sequence_number=0, ack='ACK'.encode(), origin=0):
    # We now compute our checksum by building up the packet and running our checksum function on it.
    # Our packet structure will contain our sequence number first, followed by the size of the data,
    # followed by the data itself.  We fix the size of the string being sent ... as we are sending
    # less data, it will be padded with NULL bytes, but we can handle that on the receiving end
    # just fine!

    packet_tuple = (sequence_number, origin, data)
    packet_structure = struct.Struct(f'I I {MAX_STRING_SIZE}s')
    packed_data = packet_structure.pack(*packet_tuple)
    checksum = bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

    # Now we can construct our actual packet.  We follow the same approach as above, but now include
    # the computed checksum in the packet.

    packet_tuple = (sequence_number, origin, ack, data, checksum)
    UDP_packet_structure = struct.Struct(f'I I 3s {MAX_STRING_SIZE}s 32s')
    UDP_packet = UDP_packet_structure.pack(*packet_tuple)

    # Finally, we can send out our packet over UDP and hope for the best.

    server_socket.sendto(UDP_packet, client_addrs)


# test read
def read_file(filename):
    global count
    count = 0
    for data in file_data:
        print(f"current generate packet {count}")
        count += 1
        with open(filename, "ab") as writefile:
            writefile.write(data)


# main function
def main():
    # Register our signal handler for shutting down.

    signal.signal(signal.SIGINT, signal_handler)

    print('Will wait for client connections at port ' + str(server_socket.getsockname()[1]))
    sel.register(server_socket, selectors.EVENT_READ, rdt_recv_pack)
    print('Waiting for incoming client connections ...')
    # Keep the server running forever, waiting for connections or messages.

    while (True):
        events = sel.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == '__main__':
    main()

# final11