#import neccessary python modules
import os
import geoip2.database
import simplekml

#import other script files
import constants

def find(dst_ips):
    '''Find geolocation for destination ip addresses and save results to kml file

    Parameters:
    dst_ips(list): list of unique destination ip addresses 
    '''
    
    try:
        #read GeoIP2 database and create reader object
        os.chdir(constants.SUBDIRECTORY_NAME())
        db_path = input('Paste path to GeoIP2 database here: ')
        kml = simplekml.Kml()
        reader = geoip2.database.Reader(db_path)
        
        #insert geolocation points to kml file
        point_count = 0
        for ip in dst_ips:
            try:
                rec = reader.city(ip)
                city = rec.city.name 
                country = rec.country.name
                latitude = rec.location.latitude
                longitude = rec.location.longitude
                pnt = kml.newpoint(name=ip, coords=[(longitude, latitude)], description=city)
                point_count += 1
            except geoip2.errors.AddressNotFoundError:
                print(f'Geolocation not found for ip: {ip}')
                
        # save and open kml file
        if point_count != 0:
            kml.save('destination_ips.kml')
            print('\n- OPENING KML FILE IN DEAFULT APP ----------------------------------------')
            os.startfile('destination_ips.kml')
            os.chdir('..')
        else:
            print('- NO GEOLOCATION POINTS WERE FOUND ----------------------------------------')
    except FileNotFoundError:
        print('! ERROR WHILE READING GEOIP2 DATABASE !')
