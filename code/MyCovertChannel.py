from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, sniff
import time

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - Calls the init function of the parent class.
        """
        super().__init__()
    def send(self, log_file_name, parameter1, parameter2):
        """
        - Generates a random binary message using a base class function.
        - Sends packets with specific inter-arrival times to encode the message.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        short_delay = parameter1
        long_delay = parameter2
        receiver_ip = "172.18.0.3"
        receiver_port = 8000

        for bit in binary_message:
            packet = IP(dst=receiver_ip) / UDP(dport=receiver_port)
            super().send(packet)
            
            delay = short_delay if bit == '1' else long_delay
            time.sleep(delay / 1000)  # Convert to seconds
        
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - Captures incoming packets and measures their arrival times.
        - Decodes the binary message based on inter-packet timing.
        """
        short_delay_threshold = parameter1  # Threshold to distinguish '1' (e.g., <10 ms)
        long_delay_threshold = parameter2  # Threshold to distinguish '0' (e.g., ≥10 ms)

        received_binary_message = ""
        last_arrival_time = None

        def packet_callback(packet):
            nonlocal last_arrival_time, received_binary_message

            # Measure inter-arrival time
            current_time = time.time()
            if last_arrival_time is not None:
                inter_arrival_time = (current_time - last_arrival_time) * 1000  # Convert to ms
                # Decode based on timing thresholds
                if inter_arrival_time < short_delay_threshold:
                    received_binary_message += '1'
                elif inter_arrival_time >= long_delay_threshold:
                    received_binary_message += '0'
            last_arrival_time = current_time

        # Sniff packets from the specified port
        sniff(filter="udp and dst port 8000", prn=packet_callback, timeout=parameter3)

        # Log the received message
        self.log_message(received_binary_message, log_file_name)

        self.log_message("", log_file_name)
