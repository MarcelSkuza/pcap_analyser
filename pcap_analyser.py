#import neccessary python modules
import dpkt
import sys
import os
import re
import socket

#import other script files
import geolocation
import constants
import save_results
import plot_results

def parse_pcap():
    '''Parse pcap file (specified in constants module or passed as commandline argument) and extract information about packets'''

    #OPEN AND PARSE PCAP FILE
    try:
        #open pcap file and create dpkt reader object
        if len(sys.argv) == 2:
            f = open(argv[1])
        else:
            f = open(constants.PCAP_FILE(), 'rb')
        pcap = dpkt.pcap.Reader(f)
    except IOError:
        print('! ERROR LOADING PCAP FILE !')
        print('= FINISHED RUNNING pcap_analyser.py... ========================================')
        os._exit(0)
    
    #initialize variables
    udp_count = igmp_count = tcp_count = other_count = 0
    total_igmp_len = total_udp_len = total_tcp_len = 0
    first_tcp_run = first_udp_run = first_igmp_run = True
    destination_emails = []
    source_emails = []
    image_uris = []
    src_dict = {}
    dst_dict = {}
    graph_data = {}
    ts_array = []

    #parse pcap file and extract information
    for ts, buf in pcap:
        try:
            ts_array.append(ts)
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data

            #count packets of TCP/UDP/IGMP protocols types
            if (ip.p == 17):
                if first_tcp_run:
                    first_tcp_ts = ts
                    first_tcp_run = False
                tcp_count += 1
                last_tcp_ts = ts
                total_tcp_len += len(buf)
            elif(ip.p == 6):
                if first_udp_run:
                    first_udp_ts = ts
                    first_udp_run = False
                udp_count += 1
                last_udp_ts = ts
                total_udp_len += len(buf)
            elif(ip.p == 2):
                if first_igmp_run:
                    first_igmp_ts = ts
                    first_igmp_run = False
                igmp_count += 1
                last_igmp_ts = ts
                total_igmp_len += len(buf)
                
            #extract ip addresses
            dst_ip = socket.inet_ntoa(ip.dst)
            if dst_ip in dst_dict:
                dst_dict[dst_ip] += 1
            else:
                dst_dict[dst_ip] = 1

            src_ip = socket.inet_ntoa(ip.src)
            if src_ip in src_dict:
                src_dict[src_ip] += 1
            else:
                src_dict[src_ip] = 1

            #create dictionary for network graph
            if (src_ip in graph_data) and (dst_ip in graph_data[src_ip]):
                    graph_data[src_ip][1] += 1
            else:
                graph_data[src_ip] = [dst_ip, 1.0]
        
            #extract emails and image URIs
            try:
                tcp_data = tcp.data.decode('utf-8')
                #regex adapted from: https://www.tutorialspoint.com/Extracting-email-addresses-using-regular-expressions-in-Python
                r_destination_emails = re.findall('(mailto:|[Tt]{1}[Oo]{1}: <)([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', tcp_data)
                r_source_emails = re.findall('[Ff]{1}[Rr]{1}[Oo]{1}[Mm]{1}: <([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', tcp_data)
                for email in r_destination_emails:
                        destination_emails.append(email[1])
                for email in r_source_emails:
                    source_emails.append(email)

                r_image_uris = re.findall('GET (.+\.(?:jpg|gif|png)).+\nHost: (.+)\r', tcp_data, re.MULTILINE)
                for uri_tuple in r_image_uris:
                    uri = uri_tuple[1] + uri_tuple[0]
                    image_uris.append(uri)
            except UnicodeDecodeError:
                #ignore packets which aren't 'utf-8'
                pass

        except AttributeError:
            print('! ATTRIBUTE ERROR WHILE READING PACKET !')
        except:
            print('! UNKNOWN ERROR WHILE READING PACKET !')

    f.close()
    
    #check if any packets were read
    if len(ts_array) != 0:
        pass
    else:
        print('\n- NO PACKETS WERE READ ----------------------------------------')
        print('= FINISHED RUNNING pcap_analyser.py... ========================================')
        os._exit(0)
    
    #PRINT RESULTS
    print('\n- IP OCCURANCES ----------------------------------------')
    #dictionary sorting code adapted from: https://stackoverflow.com/questions/613183/how-do-i-sort-a-dictionary-by-value
    print('\nDestination IP occurances:')
    for i in sorted(dst_dict, key=dst_dict.get, reverse=True):
        print (f'{i} -> {dst_dict[i]}')
    print('\nSource IP occurances:')
    for i in sorted(src_dict, key=src_dict.get, reverse=True):
        print (f'{i} -> {src_dict[i]}')

    if len(destination_emails) == 0:
        print('\n- NO EMAIL ADDRESSES FOUND ----------------------------------------')
    else:
        print('\n- EMAIL ADDRESSES ----------------------------------------')
        print('\nDestination email addresses:')
        for email in set(destination_emails):
            print(email)
        print('\nSource email addresses:')
        for email in set(source_emails):
            print(email)
            
    if len(image_uris) == 0:
        print('\n- NO IMAGE URIs FOUND ----------------------------------------')
    else: 
        print('\n- IMAGE URIs AND FILENAMES ----------------------------------------')
        print('\nImage URIs:')
        for uri in set(image_uris):
            print(f'URI: {uri}\nFilename: {os.path.basename(os.path.normpath(uri))}\n')

    print('\n- PACKET INFO ----------------------------------------')
    if tcp_count != 0:
        mean_tcp_len = round(total_tcp_len/tcp_count)
        print(f'\nTCP packets: {tcp_count}\nMean lenght: {mean_tcp_len}\nFirst timestamp: {first_tcp_ts}\nLast timestamp: {last_tcp_ts}\n')
    elif udp_count != 0:
        mean_udp_len = round(total_udp_len/udp_count)
        print(f'UDP packets: {udp_count}\nMean lenght: {mean_udp_len}\nFirst timestamp: {first_udp_ts}\nLast timestamp: {last_udp_ts}\n')
    elif igmp_count != 0:
        mean_igmp_len = round(total_igmp_len/igmp_count)
        print(f'IGMP packets: {igmp_count}\nMean lenght: {mean_igmp_len}\nFirst timestamp: {first_igmp_ts}\nLast timestamp: {last_igmp_ts}\n')
    else:
        print('\n- NO TCP/UDP/IGMP PACKETS FOUND ----------------------------------------')

    #CALL OTHER FUNCTIONS
    print('\n- CREATING "results" DIRECTORY... ----------------------------------------')
    save_results.create_results_dir()
    print('\n- SAVING IP OCCURANCES TO JSON FILE... ----------------------------------------')
    save_results.create_json_file(dst_dict, src_dict)
    print('\n- PLOTTING TRAFFIC... ----------------------------------------')
    plot_results.analyse_timestamps(ts_array)
    print('\n- CREATING NETWORK GRAPH... ----------------------------------------')
    plot_results.create_network_graph(graph_data, src_dict, dst_dict)
    print('\n- FINDING GEOLOCATION... ----------------------------------------\n')
    geolocation.find(dst_dict.keys())
    
