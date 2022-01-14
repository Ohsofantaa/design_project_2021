import argparse
import signal
import socket
import struct
import hashlib
import selectors
import time
# Hard code location of the server.  Not what we'll want to be doing in the assignment,
# but okay for an example like this.
import sys
from urllib.parse import urlparse

UDP_IP = "localhost"
UDP_PORT = 54321
# Define a maximum string size for the text we'll be sending along.

MAX_STRING_SIZE = 256

# The test data we want to be sending.  In this case, some text.


client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sel = selectors.DefaultSelector()
user = "leo"


def signal_handler(sig, frame):
    global user
    print('Interrupt received, shutting down ...')
    message = f'DISCONNECT {user} UDP CHAT/1.0\n'
    handle_input(message, 0)
    sys.exit(0)


# read file into a array
def handle_file(filename):
    file_data = []
    with open(filename, "rb") as readfile:
        chuck = readfile.read(256)

        while chuck:
            file_data.append(chuck)
            chuck = readfile.read(256)
    return file_data


# Simple function for setting up a prompt for the user.

def do_prompt(skip_line=False):
    if (skip_line):
        print("")
    print("> ", end='', flush=True)


# detect keyboard input from users
# handle file detect in this function
def handle_keyboard_input(file, mask):
    global user
    line = sys.stdin.readline().rstrip('\x00')
    # handle file detect here

    if line.startswith("!attach"):

        words = line.split()
        if len(words) <= 1:
            print("Your are missing filename")
        else:
            filename = ''
            try:
                filename = words[1]
                send_file(filename)
                # give a sec to timeout
                for times in range(3, 0, -1):
                    time.sleep(1)
                    print(f"{filename} has sent, server will receive after {times} second... please wait...")

                message = f"ENDOFFILE {filename} {user} {line}"
                # send into server as origin 0
                handle_input(message, 0)
                do_prompt()

            except FileNotFoundError:
                print(f"{filename} file does not exist please try again")


    else:
        sep = "&MY#SEPARATE&#"
        message = f'@{user}{sep}{line.strip()}'
        # send into server as origin 0
        handle_input(message, 0)
        do_prompt()


# rdt 2.2 ack and seq checking
# waiting for acknowledgement and check it, true is ack, false is nak
# also checking the seq number 0 positive ok 1 and negative
def is_ack(ack, seq):
    if ack == "ACK".encode() and seq == 0:
        return True
    else:
        return False


# checking the corrupt, true is not corrupt, false is corrupt
def check_corrupt(received_checksum, compute_checksum):
    if received_checksum == compute_checksum:
        return True
    else:
        return False


# recv message fro server
def rdt_recv_pack(sock, mask=0):
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

        if received_origin == 0:
            received_text = received_data.decode()
            words = received_text.strip("\n").split(' ')

            if words[0] == 'DISCONNECT':
                print('Disconnected from server ... exiting!')
                sys.exit(0)
            elif words[0] == "INVALID":
                print("Invalid username, current username has been used")
                print('Disconnected from server ... exiting!')
                sys.exit(0)
            if not received_text.startswith("ack"):
                sep = "&MY#SEPARATE&#"
                if received_text.startswith("@") and sep in received_text:
                    line = received_text.strip("\n").split(sep, 1)
                    user = line[0].strip("@:")
                    new_msg = line[1]
                    print(f"@{user}: {new_msg}")
                else:
                    print(received_text)
        # seq number check receiver corrupt happens or not
        # not corrupt and get ack and it seq number
        return received_sequence


    else:
        # packet corrupt
        print('Received and computed checksums do not match, so packet is corrupt and discarded')
        # -1 means corrupt happens
        return -1


# data is byte type
# origin 0 is from keyboard, 1 is from file
def rdt_send_pack(data, sequence_number=0, ack='ACK'.encode(), origin=0):
    global UDP_IP, UDP_PORT

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

    client_socket.sendto(UDP_packet, (UDP_IP, UDP_PORT))


# try to send file to server
def send_file(filename):
    count = 0
    corrupt_times = 0
    pack_lost_times = 0
    with open(filename, "rb") as readfile:
        chuck = readfile.read(MAX_STRING_SIZE)
        while chuck:
            try:

                seq = 0  # current waiting seq is init as 0
                rdt_send_pack(chuck, sequence_number=seq, origin=1)
                # wait for get ack from server
                while not (rdt_recv_pack(client_socket) == seq):
                    # time.sleep(1)
                    if seq == 0:
                        seq = 1
                    else:
                        seq = 0
                    print("Sequence number not not match, corrupt happens")
                    rdt_send_pack(chuck, sequence_number=seq, origin=1)
                    corrupt_times+=1

                # if get correct sequence continue loop
                chuck = readfile.read(MAX_STRING_SIZE)
                count += 1
                continue
            except socket.timeout:
                print(f"packet {count} lost")
                pack_lost_times+=1
                continue

    print(f"[{filename}] found total {count-1} packet: \n{pack_lost_times} packet lost and {corrupt_times} corrupt, and all fixed ")

# Function to handel input message
def handle_input(msgs, origns):
    flag = True
    msgs = msgs.strip('\n')
    msg = msgs.encode()
    count = 0
    while count < 5:
        try:

            seq = 0  # current waiting seq is init as 0
            rdt_send_pack(msg, sequence_number=seq, origin=origns)
            # wait for get ack from server

            while not (rdt_recv_pack(client_socket) == seq):
                # time.sleep(1)
                if seq == 0:
                    seq = 1
                else:
                    seq = 0
                print(f"command [{msgs}] has corrupts... trying to send again")
                rdt_send_pack(msg, sequence_number=seq, origin=origns)
                count += 1

            # if get correct sequence continue loop
            flag = False
            break
        except socket.timeout:
            print(f"command [{msgs}] has lost... trying to send again")
            count += 1
            continue


# Our main function.

def main():
    global UDP_IP, UDP_PORT, user
    # Register our signal handler for shutting down.

    signal.signal(signal.SIGINT, signal_handler)

    # Check command line arguments to retrieve a URL.

    parser = argparse.ArgumentParser()
    parser.add_argument("user", help="user name for this user on the chat service")
    parser.add_argument("server", help="URL indicating server location in form of chat://host:port")
    args = parser.parse_args()

    # Check the URL passed in and make sure it's valid.  If so, keep track of
    # things for later.

    try:
        server_address = urlparse(args.server)
        if ((server_address.scheme != 'chat') or (server_address.port == None) or (server_address.hostname == None)):
            raise ValueError
        UDP_IP = server_address.hostname
        UDP_PORT = server_address.port
    except ValueError:
        print('Error:  Invalid server.  Enter a URL of the form:  chat://host:port')
        sys.exit(1)

    # register two events: read data from sever and sent data to server
    try:
        user = args.user
        if user == "@all":
            raise ValueError
        # send a test msg first and get value error

        do_prompt()
        sep = "&MY#SEPARATE&#"
        line = "CHECKINGUSERNAME"
        message = f'@{user}{sep}{line}'
        rdt_send_pack(message.encode())


    except ValueError:
        print('Can not name as [@all]')
        sys.exit(1)


    sel.register(client_socket, selectors.EVENT_READ, rdt_recv_pack)
    sel.register(sys.stdin, selectors.EVENT_READ, handle_keyboard_input)
    client_socket.settimeout(0.1)
    while (True):
        events = sel.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == '__main__':
    while 1:
        main()
#a112 final11