from ChatServer import ChatServer
from log import Logger
from ENV import *

if __name__ == "__main__":
    logger = Logger('SERVER')
    logger.info("Starting server...")
    server = ChatServer()

    server.start()
    print(server.receive_message())
    server.send_message("Hello from the server!")
    server.recv_file(end_to_end=END_TO_END)
    server.close()