from ChatClient import ChatClient
from log import Logger


if __name__ == "__main__":
    logger = Logger('CLIENT')
    logger.info("Starting client...")
        
    client = ChatClient('localhost', 25565)

    client.send_message("Hello from the client!")
    print(client.receive_message())
    client.close()