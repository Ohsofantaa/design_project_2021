import socket
import os
import signal
import sys
import selectors

# Selector for helping us select incoming data and connections from multiple sources.

sel = selectors.DefaultSelector()

# Client dictionary for mapping connected clients to their connections and their command

client_list = {}
reading = False  # reading status
haveFile = False  # have received a file
filename = ''
attachMsg = ''
job = []
BUFFER = 32768


# Signal handler for graceful exiting.  We let clients know in the process so they can disconnect too.

# function to display follow list
def displaylist(x):
    value = ''
    for z in client_list[x][1]:
        value += z + " "

    return value


#
# def displayDict():
#     print('\n\ndisplay dict:')
#     global client_list
#     for x in client_list:
#         print(x + ":" + str(client_list[x][0].getpeername()[1]) + "list: " + displaylist(x))
#     print('\n\n')


def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')
    message = 'DISCONNECT CHAT/1.0\n'
    for reg in client_list:
        client_list[reg][0].send(message.encode())
    sys.exit(0)


# Read a single line (ending with \n) from a socket and return it.
# We will strip out the \r and the \n in the process.

def get_line_from_socket(sock):
    return sock.recv(BUFFER)


# Search the client list for a particular user.

def client_search(user):
    for reg in client_list:
        if reg == user:
            return client_list[reg][0]
    return None


# Search the client list for a particular user by their socket.

def client_search_by_socket(sock):
    for reg in client_list:
        if client_list[reg][0] == sock:
            return reg
    return None


# Add a user to the client list.

def client_add(user, conn):
    # second item is follow list
    client_list[user] = [conn, [f"@{user}", "@all"]]


# Remove a client when disconnected.

def client_remove(user):
    for reg in client_list:
        if reg == user:
            del client_list[reg]
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


# Function to detect a follow words in message and return users who have these key words
def detectUserList(messge):
    # print(messge)
    user_list = []
    for users in client_list:
        # compare message and client follow word list have comment
        if len(list(set(messge) & set(client_list[users][1]))) >= 1:
            user_list.append(users)
    return user_list


# Function to detect command line and processing
def detectCommand(words, user):
    command_msg = 'NO MSG'
    global reading, filename, haveFile, attachMsg

    # add items
    if words[1] == "!follow":
        if len(words) < 3:
            command_msg = f"missing the follow item!"
        else:
            if not addFollow(user, words[2]):
                command_msg = f"[{words[2]}] has in {user}'s follow list, cannot add again"
            else:
                command_msg = f"[{words[2]}] add into {user}'s follow list successful"

    # show list
    if words[1] == "!follow?":
        command_msg = ", ".join(displaylist(user).split())

    # unfollow things
    if words[1] == "!unfollow":
        if not unFollow(user, words[2]):
            command_msg = f"[{words[2]}] cannot unfollow from {user}'s follow list"
        else:
            command_msg = f"[{words[2]}] has unfollow from {user}'s follow list successful"

    # show userlist
    if words[1] == "!list":
        command_msg = displayUser()

    # exit the option
    if words[1] == "!exit":
        print('Disconnecting user ' + user)
        command_msg = "DISCONNECT DISCONNECT"
        sock = client_search(user)
        forwarded_message = f'{command_msg}\n'
        sock.send(forwarded_message.encode())
        # close and unregister
        sel.unregister(sock)
        sock.close()
        client_remove(user)
        command_msg = 'NO MSG'

    # attach options
    if "!attach" in words:
        reading = True
        # init the info
        filename_index = words.index("!attach") + 1
        filename = words[filename_index]
        attachMsg = words[filename_index - 1:]
        command_msg = f'ReadySend {filename}'

    # rest command
    if not command_msg == 'NO MSG':
        client_sock = client_search(user)
        forwarded_message = f'{command_msg}\n'
        client_sock.send(forwarded_message.encode())


# Function to send meg to user who is in the given list
def sendMsgWithList(user_list, message, user):
    if len(user_list) >= 1:
        for reg in user_list:
            if reg == user:
                continue
            else:
                client_sock = client_list[reg][0]
                forwarded_message = f'{message}\n'
                client_sock.send(forwarded_message.encode())


# Function to send file with given user
def sendFileWithList(user_list, filename, user):
    global haveFile
    sizes = os.path.getsize(filename)

    if len(user_list) >= 1:
        for reg in user_list:
            if reg == user:
                continue
            else:
                client_sock = client_list[reg][0]
                client_sock.send(f"ReadyReceive {filename} {user} {sizes} ".encode())
                with open(filename, "rb") as readfile:
                    forwarded_message = readfile.read(BUFFER)
                    while forwarded_message:
                        client_sock.send(forwarded_message)
                        forwarded_message = readfile.read(BUFFER)

    haveFile = False


# Function to read messages from clients.
def read_message(sock, mask):
    global reading, filename, haveFile, attachMsg, client_list
    msg = get_line_from_socket(sock)
    # Does this indicate a closed connection?
    try:
        message = msg.decode().strip('\n')
        if message == '':
            print('Closing connection')
            sel.unregister(sock)
            sock.close()

        else:

            checkWords = message.split()
            # change to receiving mode if some one send message into server
            if message[0] == "@" and "!attach" not in message:
                firstLetter = checkWords[0]
                user = firstLetter[firstLetter.index("@")+1:firstLetter.index(":")]
                if user in client_list:
                    reading = False
            # change to receiving mode if some one attach file in a row
            if reading and "!attach" in message:
                firstLetter = checkWords[0]
                if "@" in message and ":" in firstLetter:
                    user = firstLetter[firstLetter.index("@") + 1:firstLetter.index(":")]
                    if user in client_list:
                        reading = False
            # in the reading mode
            if reading:

                with open(filename, "wb") as writes:
                    try:
                        # read 1024 bytes from the socket (receive)
                        bytes_read = message.encode()
                        # write to the file the bytes we just received
                        writes.write(bytes_read)

                    except BlockingIOError:
                        reading = False

                user = client_search_by_socket(sock)
                user_list = detectUserList(attachMsg)
                sendFileWithList(user_list, filename, user)


            # Receive the message.
            else:
                user = client_search_by_socket(sock)
                print(f'Received message from user {user}:  ' + message)
                words = message.strip("\n").split(' ')

                # Check for client disconnections.
                if words[1] == 'DISCONNECT':
                    print('Disconnecting user ' + user)
                    client_remove(user)
                    sel.unregister(sock)
                    sock.close()

                # To detect command line and processing
                detectCommand(words, user)

                # the user who have the key word in the message
                user_list = detectUserList(words)

                if not reading:
                    # to send message to user who in the user_list
                    sendMsgWithList(user_list, message, user)
    # other file like zip
    except UnicodeDecodeError:
        job.append(msg)
        with open(filename, "wb") as writes:
            try:
                for line in job:
                    writes.write(line)
            except BlockingIOError:
                reading = False

        user = client_search_by_socket(sock)
        user_list = detectUserList(attachMsg)
        sendFileWithList(user_list, filename, user)


# Function to accept and set up clients.

def accept_client(sock, mask):
    conn, addr = sock.accept()
    print('Accepted connection from client address:', addr)
    message = get_line_from_socket(conn).decode()
    message_parts = message.split()

    # Check format of request.

    if ((len(message_parts) != 3) or (message_parts[0] != 'REGISTER') or (message_parts[2] != 'CHAT/1.0')):
        print('Error:  Invalid registration message.')
        print('Received: ' + message)
        print('Connection closing ...')
        response = '400 Invalid registration\n'
        conn.send(response.encode())
        conn.close()

    # If request is properly formatted and user not already listed, go ahead with registration.

    else:
        user = message_parts[1]

        if (client_search(user) == None):
            client_add(user, conn)
            print(f'Connection to client established, waiting to receive messages from user \'{user}\'...')
            response = '200 Registration succesful\n'
            conn.send(response.encode())
            conn.setblocking(False)
            sel.register(conn, selectors.EVENT_READ, read_message)


        # If user already in list, return a registration error.

        else:
            print('Error:  Client already registered.')
            print('Connection closing ...')
            response = '401 Client already registered\n'
            conn.send(response.encode())
            conn.close()


# Our main function.

def main():
    # Register our signal handler for shutting down.

    signal.signal(signal.SIGINT, signal_handler)

    # Create the socket.  We will ask this to work on any interface and to pick
    # a free port at random.  We'll print this out for clients to use.F

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', 0))
    print('Will wait for client connections at port ' + str(server_socket.getsockname()[1]))
    server_socket.listen(100)
    server_socket.setblocking(False)
    sel.register(server_socket, selectors.EVENT_READ, accept_client)
    print('Waiting for incoming client connections ...')

    # Keep the server running forever, waiting for connections or messages.

    while (True):
        events = sel.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)


if __name__ == '__main__':
    main()

# end of programsa1