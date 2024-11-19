import re
import Network
import argparse
from time import sleep, time
import hashlib


class Segment:
    ## the number of bytes used to store segment length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Segment.corrupt(byte_S):
            raise RuntimeError("Cannot initialize Segment: byte_S is corrupt")
        # extract the fields
        seq_num = int(
            byte_S[
                Segment.length_S_length : Segment.length_S_length
                + Segment.seq_num_S_length
            ]
        )
        msg_S = byte_S[
            Segment.length_S_length + Segment.seq_num_S_length + Segment.checksum_length :
        ]
        return self(seq_num, msg_S)

    def get_byte_S(self):
        # convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        # convert length to a byte field of length_S_length bytes
        length_S = str(
            self.length_S_length
            + len(seq_num_S)
            + self.checksum_length
            + len(self.msg_S)
        ).zfill(self.length_S_length)
        # compute the checksum
        checksum = hashlib.md5((length_S + seq_num_S + self.msg_S).encode("utf-8"))
        checksum_S = checksum.hexdigest()
        # compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S

    @staticmethod
    def corrupt(byte_S):
        # extract the fields
        length_S = byte_S[0 : Segment.length_S_length]
        seq_num_S = byte_S[
            Segment.length_S_length : Segment.seq_num_S_length + Segment.seq_num_S_length
        ]
        checksum_S = byte_S[
            Segment.seq_num_S_length
            + Segment.seq_num_S_length : Segment.seq_num_S_length
            + Segment.length_S_length
            + Segment.checksum_length
        ]
        msg_S = byte_S[
            Segment.seq_num_S_length + Segment.seq_num_S_length + Segment.checksum_length :
        ]

        # compute the checksum locally
        checksum = hashlib.md5(str(length_S + seq_num_S + msg_S).encode("utf-8"))
        computed_checksum_S = checksum.hexdigest()
        # and check if the same
        return checksum_S != computed_checksum_S


class SWRDT:
    ## latest sequence number used in a segment
    seq_num = 1
    ## buffer of bytes read from network
    byte_buffer = ""

    def __init__(self, role_S, receiver_S, port):
        self.network = Network.NetworkLayer(role_S, receiver_S, port)

    def disconnect(self):
        self.network.disconnect()

    def swrdt_send(self, msg_S):
        # Create and send the segment
        p = Segment(self.seq_num, msg_S)
        self.network.network_send(p.get_byte_S())
        print(f"Send message {p.seq_num}")
        # Start in waiting for ACK state
        state = "SB"
        timer = 2
        timer_start = None
        while True:
            if state == "SB":
                # Wait for an acknowledgement
                ack_S = self.network.network_receive()
                timer_start = time()

                while time() - timer_start < timer:
                    if ack_S:
                        try:
                            ack_segment = Segment.from_byte_S(ack_S)
                            if not Segment.corrupt(ack_S) and ack_segment.seq_num == self.seq_num:
                                # Acknowledgement is valid
                                print(f"Receive ACK {ack_segment.seq_num}. Message successfully sent!")
                                self.seq_num += 1
                                state = "SA"
                                break
                            else:
                                # Acknowledgement is invalid, resend the segment
                                print(f"Receive ACK {ack_segment.seq_num}. Resend message {p.seq_num}")
                                state = "SB"
                                self.network.network_send(p.get_byte_S())
                        except RuntimeError:
                            print(f"Corruption detected in ACK. Resend message {p.seq_num}")
                            self.network.network_send(p.get_byte_S())
                            state = "SB"

                    ack_S = self.network.network_receive()
                if state == "SB":
                    # Timeout, resend the segment
                    print(f"Timeout! Resend message {p.seq_num}")
                    self.network.network_send(p.get_byte_S())
                    continue
            elif state == "SA":
                break



    def swrdt_receive(self):
        ret_S = None
        byte_S = self.network.network_receive()


        self.byte_buffer += byte_S
        # keep extracting segments
        while True:
            if len(self.byte_buffer) < Segment.length_S_length:
                return ret_S  # not enough bytes to read segment length
            # extract length of segment
            length = int(self.byte_buffer[: Segment.length_S_length])
            if len(self.byte_buffer) < length:
                return ret_S  # not enough bytes to read the whole Segment
            # create Segment from buffer content and add to return string
            try:
                p = Segment.from_byte_S(self.byte_buffer[0:length])
            except RuntimeError:
                # Byte is corrupt, resend the previous acknowledgement
                ack_segment = Segment(self.seq_num - 1, "ACK")
                self.network.network_send(ack_segment.get_byte_S())
                print(f"Corruption detected! Send ACK {ack_segment.seq_num}")
                self.byte_buffer = self.byte_buffer[length:]
                continue
            
            recv_seq_num = p.seq_num

            self.byte_buffer = self.byte_buffer[length:]
            # if this was the last Segment, will return on the next iteration
            if recv_seq_num == self.seq_num - 1:
                # Resend the previous acknowledgement
                ack_segment = Segment(self.seq_num - 1, "ACK")
                self.network.network_send(ack_segment.get_byte_S())
            elif recv_seq_num == self.seq_num:
                # Deliver the message to the application layer
                ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                # Send an acknowledgement
                ack_segment = Segment(recv_seq_num, "ACK")
                self.network.network_send(ack_segment.get_byte_S())
                self.seq_num += 1
                print(f"Receive message {recv_seq_num}. Send ACK {ack_segment.seq_num}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SWRDT implementation.")
    parser.add_argument(
        "role",
        help="Role is either sender or receiver.",
        choices=["sender", "receiver"],
    )
    parser.add_argument("receiver", help="receiver.")
    parser.add_argument("port", help="Port.", type=int)
    args = parser.parse_args()

    swrdt = SWRDT(args.role, args.receiver, args.port)
    if args.role == "sender":
        swrdt.swrdt_send("MSG_FROM_SENDER")
        sleep(2)
        print(swrdt.swrdt_receive())
        swrdt.disconnect()

    else:
        sleep(1)
        print(swrdt.swrdt_receive())
        swrdt.swrdt_send("MSG_FROM_RECEIVER")
        swrdt.disconnect()
