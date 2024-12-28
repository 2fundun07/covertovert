from CovertChannelBase import CovertChannelBase
from scapy.all import Ether, LLC, Raw, IP, sniff
import time
import socket

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self, threshold_ms=300, error_ms=150):
        """
        - Calls the init function of the parent class.
        """
        super().__init__()
        self.send_time_0_max = threshold_ms - error_ms
        self.send_time_1_min = threshold_ms + error_ms
        self.send_time_1_max = 2 * threshold_ms

        self.receive_time_0_1 = threshold_ms
        self.receive_time_1_max = 3 * threshold_ms
        
        self.timestamp = 0
        self.message = ""
        self.lastconvertedMessage = ""
        self.lastmessage = ""

    def send(self, log_file_name, parameter1, parameter2):
        """
        - Generates a random binary message using the parent class function.
        - logs the message
        - Sends LLC packets with specific inter-arrival times to encode the message, where a short delay encodes 1 and a long delay encodes 0.
        """
        message_to_transfer = self.generate_random_binary_message_with_logging(log_file_name)
        llc = LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        ether = Ether() / IP(dst="receiver") / llc

        dummy_message = self.generate_random_message()
        packet = ether / Raw(dummy_message)
        super().send(packet)
        
        for bit in message_to_transfer:
            dummy_message = self.generate_random_message()
            packet = ether / Raw(dummy_message)
            super().send(packet)

            if bit == '0':
                self.sleep_random_time_ms(0, self.send_time_0_max)
            elif bit == '1':
                self.sleep_random_time_ms(self.send_time_1_min, self.send_time_1_max)
        
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - Captures incoming LLC packets and measures their arrival times.
        - Decodes the binary message based on inter-packet timing with the same consensus as the sender.
        """
        def packet_handler(packet):
            """
            Handles each received packet to decode the covert timing channel.
            - Measures the inter-arrival time and translates it into a binary bit (0 or 1).
            - Converts the received bits into characters and adds them to the message.
            """
            currentTime = time.time()

            # If it's the first packet, store the timestamp
            if self.timestamp == 0:
                self.timestamp = currentTime
                return

            # Calculate the inter-arrival time in milliseconds
            timeDifferenceMs = (currentTime - self.timestamp) * 1000
            self.timestamp = currentTime

            print(timeDifferenceMs)

            # Decode bit based on inter-arrival time
            if 0 <= timeDifferenceMs <= self.receive_time_0_1:
                self.message += "0"
            elif self.receive_time_0_1 <= timeDifferenceMs:
                self.message += "1"

            # Convert 8 bits into a character
            if len(self.message) == 8:
                convertedMessage = self.convert_eight_bits_to_character(self.message)
                self.message = ""
                self.lastmessage += convertedMessage
                self.lastconvertedMessage = convertedMessage
            
            if self.lastconvertedMessage == ".":
                raise Exception("End of the message")

        try:
            sniff(prn=packet_handler, filter="ip src 172.18.0.2", timeout = parameter3)
        except Exception as e:
            print("Dot")

        print("here")
        self.lastmessage += "."
        self.log_message(self.lastmessage, log_file_name)
