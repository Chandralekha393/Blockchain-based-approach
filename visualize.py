from classes import TrafficGenerator, Node, BroadcastPacketPipe, Consensus
import time
import random
import matplotlib.pyplot as plt
import numpy as np

MALICIOUS_NODE_THRESHOLD_SCORE = 40


data_x_axis = {}
data_y_axis = {}



def plot_node_scores():
    fig, ax = plt.subplots()
    for node in sorted(data_x_axis.keys(), key=lambda x:x.node_number):
       ax.plot(data_x_axis[node], data_y_axis[node], label = 'Node {} : Malware Prob : {:.2f}'.format(node.node_number, node.ignore_malicious_packet_prob))

    #plt.legend(loc="lower right", title="Nodes with Malicious Probabilty", frameon=False)
    plt.xlabel("Number of iterations")
    plt.ylabel("Trust Score")
    plt.show() 

if __name__ == "__main__":
    number_of_nodes = 30
    timestep = 600
    node_list = []
    broadcast_pipe = BroadcastPacketPipe()
    malware_prob        =  [ random.random() for i in range(number_of_nodes)]
    false_positive_prob = malware_prob

    malware_prob = [0.1, 0.5, 1.0, 0.2 , 0.3, 0.09, 0.8, 0.01, 1.0, 1.0, 0.1, 0.5, 1.0, 0.2 , 0.3, 0.09, 0.8, 0.01, 1.0, 1.0, 0.1, 0.5, 1.0, 0.2 , 0.3, 0.09, 0.8, 0.01, 1.0, 1.0]
    false_positive_prob = malware_prob
    for i in range(number_of_nodes):
        node = Node(i + 1, broadcast_pipe,  node_list=node_list, 
                                            ignore_malicious_packet_prob=malware_prob[i],
                                            false_positve_prob=false_positive_prob[i])


        node_pipe = node.get_traffic_pipe()
        traffic_gen = TrafficGenerator(node, number_of_nodes, node_pipe)
        node_list.append((node, traffic_gen))
        data_x_axis[node] = []
        data_y_axis[node] = []

    consensus = Consensus(node_list)

    for _time in range(timestep):
        for node, traffic_generator in node_list:
            traffic_generator.generate_packets()
            node.process_traffic()
        
        consensus.decision()
            

        print('==================================== {} ===================================='.format(_time))
        for node, traffic_generator in node_list:
            print(node)
            data_x_axis[node].append(_time)
            data_y_axis[node].append(node.get_trust_score())
            if node.get_trust_score() < MALICIOUS_NODE_THRESHOLD_SCORE:
                node_list.remove((node, traffic_generator))
                print('Malicious Node : {}'.format(node))

        #time.sleep(0.1)

        
    plot_node_scores()
