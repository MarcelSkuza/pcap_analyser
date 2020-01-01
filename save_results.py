#import neccessary python modules
import json
import os
import shutil

#import other script files
import constants

def create_results_dir():
    '''Create subdirectory for storing results'''
    
    if os.path.exists(constants.SUBDIRECTORY_NAME()):
        shutil.rmtree(constants.SUBDIRECTORY_NAME())
    os.mkdir(constants.SUBDIRECTORY_NAME())
    
def create_json_file(dst_dict, src_dict):
    '''Create JSON file containing ip address occurances in the file

    Parameters:
    dst_dict(dict): dictionary storing destination ip address as keys and number of occurances as values
    src_dict(dict): dictionary storing source ip address as keys and number of occurances as values
    '''
    
    os.chdir(constants.SUBDIRECTORY_NAME())
    with open('ip_occurances.json', 'a+') as json_file:
        json.dump(dst_dict, json_file, indent=2)
        json_file.write('\n')
        json.dump(src_dict, json_file, indent=2)
        json_file.write('\n')
    os.chdir('..')
    
