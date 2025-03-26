from ChatClient import ChatClient
from log import Logger
from ENV import *


if __name__ == "__main__":
    logger = Logger('CLIENT')
    logger.info("Starting client...")
        
    client = ChatClient('localhost', 25565)

    client.send_message("Hello from the client!")
    print(client.receive_message())
    client.send_file("LICENSE", end_to_end=END_TO_END)
    client.close()