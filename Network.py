import argparse
import socket
import threading
from time import sleep
import random
import SWRDT


## Provides an abstraction for the network layer
class NetworkLayer:
    # configuration parameters
    prob_pkt_loss = 0.2
    prob_byte_corr = 0.2
    prob_pkt_reorder = 0

    # class variables
    sock = None
    conn = None
    buffer_S = ""
    lock = threading.Lock()
    collect_thread = None
    stop = None
    socket_timeout = 0.1
    reorder_msg_S = None

    def __init__(self, role_S, receiver_S, port):
        if role_S == "sender":
            print("Network: role is sender")
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect((receiver_S, port))
            self.conn.settimeout(self.socket_timeout)

        elif role_S == "receiver":
            print("Network: role is receiver")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(("localhost", port))
            self.sock.listen(1)
            self.conn, addr = self.sock.accept()
            self.conn.settimeout(self.socket_timeout)

        # start the thread to receive data on the connection
        self.collect_thread = threading.Thread(name="Collector", target=self.collect)
        self.stop = False
        self.collect_thread.start()

    def disconnect(self):
        if self.collect_thread:
            self.stop = True
            self.collect_thread.join()

    def __del__(self):
        if self.sock is not None:
            self.sock.close()
        if self.conn is not None:
            self.conn.close()

    def network_send(self, msg_S):
        # return without sending if the packet is being dropped
        if random.random() < self.prob_pkt_loss:
            return
        # corrupt a packet
        if random.random() < self.prob_byte_corr:
            start = random.randint(SWRDT.Segment.length_S_length, len(msg_S) - 5)
            num = random.randint(1, 5)
            repl_S = "".join(random.sample("XXXXX", num))  # sample length >= num
            msg_S = msg_S[:start] + repl_S + msg_S[start + num :]
        # reorder packets - either hold a packet back, or if one held back then send both
        if random.random() < self.prob_pkt_reorder or self.reorder_msg_S:
            if self.reorder_msg_S is None:
                self.reorder_msg_S = msg_S
                return None
            else:
                msg_S += self.reorder_msg_S
                self.reorder_msg_S = None

        # keep calling send until all the bytes are transferred
        totalsent = 0
        while totalsent < len(msg_S):
            sent = self.conn.send(msg_S[totalsent:].encode("utf-8"))
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

    ## Receive data from the network and save in internal buffer
    def collect(self):
        #         print (threading.currentThread().getName() + ': Starting')
        while True:
            try:
                recv_bytes = self.conn.recv(4096)
                with self.lock:
                    self.buffer_S += recv_bytes.decode("utf-8")
            # you may need to uncomment the BlockingIOError handling on Windows machines
            #             except BlockingIOError as err:
            #                 pass
            except socket.timeout as err:
                pass
            if self.stop:
                #                 print (threading.currentThread().getName() + ': Ending')
                return

    ## Deliver collected data to sender
    def network_receive(self):
        with self.lock:
            ret_S = self.buffer_S
            self.buffer_S = ""
        return ret_S


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network layer implementation.")
    parser.add_argument(
        "role",
        help="Role is either sender or receiver.",
        choices=["sender", "receiver"],
    )
    parser.add_argument("receiver", help="receiver.")
    parser.add_argument("port", help="Port.", type=int)
    args = parser.parse_args()

    network = NetworkLayer(args.role, args.receiver, args.port)
    if args.role == "sender":
        network.network_send("MSG_FROM_SENDER")
        sleep(2)
        print(network.network_receive())
        network.disconnect()

    else:
        sleep(1)
        print(network.network_receive())
        network.network_send("MSG_FROM_RECEIVER")
        network.disconnect()
