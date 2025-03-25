from ChatServer import ChatServer
from log import Logger

if __name__ == "__main__":
    logger = Logger('SERVER')
    logger.info("Starting server...")
    server = ChatServer()

    server.start()
    print(server.receive_message())
    server.send_message("Hello from the server!")
    server.close()