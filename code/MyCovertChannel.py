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

        packet = IP(dst=receiver_ip) / UDP(dport=receiver_port)
        super().send(packet)
        time.sleep(short_delay / 1000)

        for  i in range(10):
            packet = IP(dst=receiver_ip) / UDP(dport=receiver_port)
            super().send(packet)
            delay = short_delay
            time.sleep(delay / 1000)
        
        for  i in range(10):
            packet = IP(dst=receiver_ip) / UDP(dport=receiver_port)
            super().send(packet)
            delay = long_delay
            time.sleep(delay / 1000)
        
        for bit in binary_message:
            packet = IP(dst=receiver_ip) / UDP(dport=receiver_port)
            super().send(packet)
            
            if bit == '1':
                delay = short_delay
            else:
                delay = long_delay
            time.sleep(delay / 1000)  # Convert to seconds
        
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - Captures incoming packets and measures their arrival times.
        - Decodes the binary message based on inter-packet timing.
        """
        received_binary_message = ""
        received_message = ""
        last_arrival_time = None
        short_threshold = None
        long_threshold = None
        threshold = 0
        network_delay_samples = []

        def packet_callback(packet):
            nonlocal last_arrival_time, received_binary_message, received_message, short_threshold, long_threshold, network_delay_samples, threshold

            # Measure inter-arrival time
            current_time = time.time()
            if last_arrival_time is not None:
                inter_arrival_time = (current_time - last_arrival_time) * 1000  # Convert to ms
                # Decode based on timing thresholds
                print(inter_arrival_time)
                if len(network_delay_samples) < 10 and short_threshold is None:
                    network_delay_samples.append(inter_arrival_time)

                elif len(network_delay_samples) == 10 and short_threshold is None:
                    short_threshold = sum(network_delay_samples) / 10
                    network_delay_samples = []

                elif len(network_delay_samples) < 10 and long_threshold is None:
                    network_delay_samples.append(inter_arrival_time)
                
                elif len(network_delay_samples) == 10 and long_threshold is None:
                    long_threshold = sum(network_delay_samples) / 10
                    threshold = (short_threshold + long_threshold) / 2
                    
                    if inter_arrival_time < threshold:
                        received_binary_message += '1'

                    elif inter_arrival_time >= threshold:
                        received_binary_message += '0'

                elif inter_arrival_time < threshold:
                    received_binary_message += '1'

                elif inter_arrival_time >= threshold:
                    received_binary_message += '0'

                length = len(received_binary_message)
                if (length == 8):
                    msg = self.convert_eight_bits_to_character(received_binary_message)
                    received_message += msg
                    received_binary_message = ""
            last_arrival_time = current_time

        # Sniff packets from the specified port
        sniff(filter="udp and dst port 8000", prn=packet_callback, timeout=parameter3)

        # Log the received message
        self.log_message(received_message, log_file_name)
