"""
CSN08114 Coursework - pcap file analyser
Author: Marcel Skuza
Last modified: 30/11/2019
"""

#import other script files
import pcap_analyser

def main():
    '''Main function in script'''

    print('= RUNNING pcap_analyser.py... ========================================')
    pcap_analyser.parse_pcap()
    print('= FINISHED RUNNING pcap_analyser.py... ========================================')

main()
