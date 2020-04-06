
import random
import itertools
from collections import deque

packet_seed = 1


class Packet():
    packet_number =  1
    def __init__(self, numberOfNodes, isMalicious=False):
        Packet.packet_number += 1
        self.packet_number = Packet.packet_number
        self.processing_node = None
        self.isMalicious = isMalicious
        self.accessCount = numberOfNodes
        self.node_classification_result = None

    def __str__(self):
        return 'Packet Number : {:5} | Node : {:2} | isMalicious :\t{}\t| isMalClassified :\t{}\t| Access Count : {:1}'.format(
                                                                self.packet_number, 
                                                                self.processing_node.node_number, 
                                                                self.isMalicious, 
                                                                self.node_classification_result,
                                                                self.accessCount)


class BroadcastPacketPipe(object):
    def __init__(self, capacity=10):
        self.capacity = capacity
        self.pipes = deque(maxlen=capacity)

    def get(self):
        packet = self.pipes[0]
        packet.accessCount = packet.accessCount - 1
        if packet.accessCount == 0:
            return self.pipes.popleft()

        return packet

    def put(self, value):
        self.pipes.append(value)

    def isEmpty(self):
        return len(self.pipes) == 0


class Consensus():
    def __init__(self, node_list, consensus_threshold=0.50):
        self.node_list = node_list
        self.consensus_threshold = consensus_threshold

    def decision(self):
        num_nodes = len(self.node_list)
        if num_nodes < 2:
            return True

        num_of_agreeing_nodes = 0
        consensus_decision = True
        for node, tg in self.node_list:
            packet, decision = node.check_broadcast_packets()
            if packet is not None and decision is True and node.node_number != packet.processing_node.node_number:
                num_of_agreeing_nodes += 1

        if packet is not None:
            result = num_of_agreeing_nodes / (num_nodes - 1)
            consensus_decision = self.consensus_threshold < result
            if consensus_decision:
                packet.processing_node.increase_correct_alerts()
                packet.processing_node.trust_score_increase()
            else:
                packet.processing_node.increase_incorrect_alerts()
                packet.processing_node.trust_score_decrease()

            print("Consensus : {}\t=> {}".format(consensus_decision, packet))
        
        return consensus_decision



class TrafficGenerator:
    def __init__(self, node, numberOfNodes, traffic_pipe, malicious_prob=0.2):
        self.corresponding_node = node
        self.traffic_pipe = traffic_pipe
        self.malicious_prob = malicious_prob
        self.packet_number = 0
        self.numberOfNodes = numberOfNodes

    def generate_packets(self):
        isMalicious = False
        mal_prob = random.random()
        if mal_prob < self.malicious_prob:
            isMalicious = True

        packet = Packet(self.numberOfNodes, isMalicious=isMalicious)
        self.packet_number += 1
        packet.packet_number = self.packet_number
        self.traffic_pipe.append(packet)


class Node:
    def __init__(self, node_number, node_broadcast_pipe,
                 ignore_malicious_packet_prob=1, false_positve_prob=0.4,
                 false_negative_prob=0.2, recent_buffer_length=10, trust_score=50, node_list=[], request_prob=0.4):
        self.trust_score = trust_score
        self.false_positve_prob = false_positve_prob
        self.false_negative_prob = false_negative_prob
        self.node_number = node_number
        self.ignore_malicious_packet_prob = ignore_malicious_packet_prob
        self.packet_buffer = deque(maxlen=recent_buffer_length)
        self.traffic_buffer = deque(maxlen=10)
        self.node_broadcast_pipe = node_broadcast_pipe
        self.node_list = node_list
        self.request_prob = request_prob
        self.packets_processed = 0
        self.correct_alerts = 0
        self.incorrect_alerts = 0

    def isPacketMalicious(self, packet):
        mal_prob = random.random()
        isMalicious =  False
        if packet.isMalicious:
            if mal_prob < self.ignore_malicious_packet_prob:
                isMalicious = False
            else:
                isMalicious = True
        else:
            if mal_prob < self.false_positve_prob:
                isMalicious = True
            else:
                isMalicious = False
        
        return isMalicious

    def broadcast_packet(self, packet):
        packet.processing_node = self
        self.node_broadcast_pipe.put(packet)

    def increase_correct_alerts(self):
        self.correct_alerts += 1

    def increase_incorrect_alerts(self):
        self.incorrect_alerts += 1

    def trust_score_increase(self):
        self.trust_score += self.correct_alerts/self.packets_processed
        self.trust_score = min(self.trust_score, 100)

    def trust_score_decrease(self):
        self.trust_score -=   self.incorrect_alerts/self.packets_processed
        self.trust_score = max(self.trust_score, 0)

    def check_broadcast_packets(self):
        if not self.node_broadcast_pipe.isEmpty():
            packet = self.node_broadcast_pipe.get()
            if packet.processing_node.node_number != self.node_number:
                packet_result = self.isPacketMalicious(packet)
                return packet, packet_result == packet.node_classification_result
            else:
                return packet, True
        else:
            return None, None


    def return_past_traffic(self, number_packets=5):
        return list(itertools.islice(self.packet_buffer, 0, number_packets))

    def process_packet(self):
        packet = self.get_packet()
        result = self.isPacketMalicious(packet)
        packet.node_classification_result = result
        self.packets_processed += 1
        #print(packet)
        if result:
            self.broadcast_packet(packet)

    def get_packet(self):
        packet = self.traffic_buffer.popleft()
        packet.processing_node = self
        self.packet_buffer.append(packet)
        return packet

    def get_traffic_pipe(self):
        return self.traffic_buffer

    def analyze_past_activity(self, activity):
        total_packets = len(activity)
        correct_classification = 0
        incorrect_classification = 0
        if total_packets == 0:
            return
        source_node = activity
        for packet in activity:
            original_classification = packet.node_classification_result
            new_classification = self.isPacketMalicious(packet)
            if original_classification == new_classification:
                packet.processing_node.increase_correct_alerts()
                packet.processing_node.trust_score_increase()
            else:
                packet.processing_node.increase_incorrect_alerts()
                packet.processing_node.trust_score_decrease()

    def process_past_activity(self):
        req_prob = random.random()
        if req_prob < self.request_prob:
            number_of_nodes = len(self.node_list)
            random_node_index = random.randint(0, number_of_nodes - 1)
            node, tg = self.node_list[random_node_index]
            if node.node_number != self.node_number:
                past_activity = node.return_past_traffic()
                self.analyze_past_activity(past_activity)

    def process_traffic(self):
        self.process_packet()
        self.process_past_activity()

    def consensus(self):
        self.check_broadcast_packets()

    def get_trust_score(self):
        return self.trust_score

    def __str__(self):
        return 'Node {:2} : Trust Score : {:.4f} | Ignore | {:2} | False Positive : {:2}'.format(self.node_number, 
                                                                                        self.get_trust_score(),
                                                                                        self.ignore_malicious_packet_prob,
                                                                                        self.false_positve_prob)
