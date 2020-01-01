#import neccessary python modules
import os
import datetime
import statistics
import matplotlib.pyplot as plt
import networkx as nx

#import other script files
import constants

def analyse_timestamps(ts_array):
    '''Count packets transfered during time interval (specified in constants) based on packet timestamps

    Parameters:
    ts_array(array): array of packet timestamps
    '''

    try:
        ts_dict = {}
        prev_ts = ts_array[0]
        capture_date = datetime.date.fromtimestamp(ts_array[0])
        count_packets = 0
        #count number of packets during time interval
        for i in ts_array:
            if i <  prev_ts + constants.INTERVAL():
                count_packets += 1
            else:
                count_packets += 1
                #convert timestamp to datetime format and store as key in ts_dict
                ts_dict[datetime.datetime.fromtimestamp(prev_ts)] = count_packets
                prev_ts = i
                count_packets = 0
        #calculate heavy traffic treshold and call function to plot packets against time
        mean_packet_amount = sum(ts_dict.values())/len(ts_dict.values())
        treshold = mean_packet_amount + 2*statistics.stdev(ts_dict.values())
        create_traffic_plot(ts_dict, capture_date, treshold)
    except:
        print('! ERROR WHILE ANALYSING TIMESTAMPS, DECREASE INTERVAL CONSTANT !')
        
def create_traffic_plot(ts_dict, capture_date, treshold):
    '''Creates and saves line chart of number of packets against time

    Parameters:
    ts_dict(dictionary): dictionary storing timestamp as keys and number of packets transfered as values
    capture_date(datetime.date): date of packet capture
    treshold(float): heavy traffic treshold
    '''

    #create plot using matplotlib
    plt.rcParams.update({'font.size': 8})
    traffic_plot = plt.plot(list(ts_dict.keys()), list(ts_dict.values()))
    plt.axhline(y=treshold, color='r', linestyle='--', label='heavy traffic treshold')
    plt.legend()
    plt.ylabel('number of packets')
    plt.xlabel('time captured')
    plt.title(f'Packet capture, {capture_date}')
    
    #save and display plot
    os.chdir(constants.SUBDIRECTORY_NAME())
    plt.savefig('traffic_plot.png', format='PNG', dpi=1000)
    os.startfile('traffic_plot.png')
    os.chdir('..')

    #IGNORE - bug workaround (need to show and close plot)
    plt.show(block=False)
    plt.close()
    
def create_network_graph(graph_data, src_dict, dst_dict):
    '''Create and save weighted, multidirectional graph of the network 

    Parameters:
    graph_data(list): list of edges (ip addresses) and weights (occurances), neccessary to draw graph 
    src_dict(dict): dictionary storing source ip address as keys and number of occurances as values
    dst_dict(dict): dictionary storing destination ip address as keys and number of occurances as values
    '''

    #create network graph using networkx
    edge_list = []
    width_list = []
    node_list = list(src_dict.keys() | dst_dict.keys())
    for key, value in graph_data.items():
        edge_list.append((key, value[0], value[1]))
        width_list.append(value[1]/constants.WIDTH_NORMALISATION_FACTOR())
    G = nx.MultiDiGraph()
    G.add_nodes_from(node_list)
    G.add_weighted_edges_from(edge_list)
    nx.draw_networkx_labels(G, pos=nx.circular_layout(G, scale=1.09), font_size=4, font_weight='bold')
    nx.draw(G, pos=nx.circular_layout(G), width=width_list, node_size=350, alpha = 0.7)

    #save and display graph
    os.chdir(constants.SUBDIRECTORY_NAME())
    plt.savefig('network_graph.png', format='PNG', dpi=1000)
    os.startfile('network_graph.png')
    os.chdir('..')
