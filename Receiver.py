import argparse
import SWRDT
import time

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Uppercase conversion receiver.")
    parser.add_argument("port", help="Port.", type=int)
    args = parser.parse_args()

    timeout = 10  # close connection if no new data within 10 seconds
    time_of_last_data = time.time()

    swrdt = SWRDT.SWRDT("receiver", None, args.port)
    while True:
        # print("this is a print")
        # try to receive message before timeout
        msg_S = swrdt.swrdt_receive()
        if msg_S is None:
            if time_of_last_data + timeout < time.time():
                break
            else:
                continue
        time_of_last_data = time.time()

        # print("Received Message:", msg_S)


    swrdt.disconnect()
