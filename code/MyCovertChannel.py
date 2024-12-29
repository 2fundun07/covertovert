from CovertChannelBase import CovertChannelBase
import time
from scapy.all import sniff
from scapy.all import Ether, LLC, Raw, IP

class MyCovertChannel(CovertChannelBase):
    """
    This covert channel exploits timing intervals between packets (inter-arrival times) 
    to encode and transfer binary information stealthily over the network using LLC packets.
    """
    def __init__(self):
        """
        Initializes the covert channel class with necessary variables:
        - `timestamp` tracks the last packet's arrival time.
        - `msg_bits` stores bits received from timing intervals.
        - `received_msg` stores the reconstructed message.
        """
        super().__init__()        
        self.timestamp = 0
        self.msg_bits = ""
        self.received_msg = ""

    def send(self, log_file_name, threshold_ms, error_ms):
        """
        Encodes a binary message into timing intervals and sends it over the network:
        - `threshold_ms` defines the timing threshold to distinguish between '0' and '1'.
        - `error_ms` adds tolerance to handle noise and jitter.
        - Randomly generated binary messages are logged and then transmitted using LLC packets.
        - Intervals between packets are modulated to represent '0' or '1'.
        """
        message_to_transfer = self.generate_random_binary_message_with_logging(log_file_name, 16, 16)
        llc = LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        ether = Ether() / IP(dst="receiver") / llc

        # Define timing intervals for '0' and '1' based on the threshold and error
        max_0_time = threshold_ms - error_ms
        min_1_time = threshold_ms + error_ms
        max_1_time = 2 * threshold_ms

        start_time = time.time()

        # Send an initial dummy packet
        dummy_message = self.generate_random_message()
        packet = ether / Raw(dummy_message)
        super().send(packet)

        a = 0
        for bit in message_to_transfer:
            t0 = time.time()
            a += 1
            #print(f"a: {a}, bit: {bit}")

            # Send a packet after the timing delay
            dummy_message = self.generate_random_message()
            packet = ether / Raw(dummy_message)
            if bit == '0':
                self.sleep_random_time_ms(0, max_0_time)
            elif bit == '1':
                self.sleep_random_time_ms(min_1_time, max_1_time)
            super().send(packet)
            t1 = time.time()
            #print((t1-t0)*1000)

        end_time = time.time()

        print(f"The covert channel capacity is {128/(end_time - start_time)} byte per seconds.")
        
        
    def receive(self, log_file_name, threshold_ms, error_ms, src_ip):
        """
        Receives and decodes binary information from timing intervals between packets:
        - Calculates inter-arrival times to determine whether each bit is '0' or '1'.
        - Reconstructs the binary message, converts it to characters, and logs the result.
        - Uses `threshold_ms` to differentiate between '0' and '1'.
        - Stops decoding when a termination character (e.g., '.') is received.
        """
        max_1_time = 3 * threshold_ms

        def packet_handler(packet):
            currentTime = packet.time

            # Calculate time difference between consecutive packets
            timeDifferenceMs = (currentTime - self.timestamp) * 1000
            #print(timeDifferenceMs)

            # If this is the first packet, initialize the timestamp
            if self.timestamp == 0:
                self.timestamp = packet.time
                return

            # Determine the bit ('0' or '1') based on the timing difference
            if 0 <= timeDifferenceMs <= (threshold_ms + error_ms):
                self.msg_bits += "0"
            else:
                self.msg_bits += "1"

            #print(self.msg_bits)

            # Convert 8 bits to a character and add it to the message
            if len(self.msg_bits) == 8:
                convertedMessage = self.convert_eight_bits_to_character(self.msg_bits)
                self.msg_bits = ""
                self.received_msg += convertedMessage
                #print(self.received_msg)
            
            # Stop processing when the termination character is received
            if len(self.received_msg) > 1 and self.received_msg[-1] == ".":
                raise Exception()
            
            self.timestamp = packet.time
        
        try:
            # Sniff incoming packets from the specified source IP
            sniff(prn=packet_handler, filter=f"ip src {src_ip}")
        except Exception as e:
            print("Termination char is received.")

        # Log the reconstructed message
        self.log_message(self.received_msg, log_file_name)
