
import scapy.all as scapy
import argparse
from mac_vendor_lookup import MacLookup
from datetime import datetime
import pandas as pd
import csv

def get_args():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', '--ipTarget', dest='ipTarget', help='Target IP Address/Adresses')
    options = parser.parse_args()


    if not options.ipTarget:
        parser.error("[-] Por favor, especifique um IP")
    return options

collectionFirst = datetime.now()
def scan(ip):
    
    arp_request = scapy.ARP(pdst = ip)

    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    
    broadcast_arp_request = broadcast / arp_request

    answered_list = scapy.srp(broadcast_arp_request, timeout = 1, verbose = False)[0]
    devices_list = []
    for i in range(0,len(answered_list)):
        device_info = {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc}
        devices_list.append(device_info)
        #print(devices_list)

    return devices_list



def getDateTime(result):

    for i in result:
        i["CollectionFirst"] = collectionFirst_formatted = collectionFirst.strftime("%Y-%m-%d %H:%M:%S")

    return result

def find_vendor(mac_address):
    mac = MacLookup()
    try:
        result = mac.lookup(mac_address)
    except:
        mac.update_vendors()
        result = mac.lookup(mac_address)
        
    return result

def searchManufacturer(result):

    for i in result:
        i["manufacturer"] = find_vendor(i["mac"])

    return result



def save_data_to_csv(devices_df):
    print(f'Reading file: ')

    try:
        old_df = pd.read_csv(f'discovery.csv')
        df_compare = devices_df[~devices_df['mac'].isin(old_df['mac'])]
        print(df_compare)
        final_df = pd.concat([old_df, df_compare], ignore_index=True)

        final_df.to_csv(f'discovery.csv', index=False)
        #print(final_df)
    except:
        print(f'File not found, creating a new one')
        new_file = devices_df.to_csv(f'discovery.csv', index=False)
        print(f'File created successfully.')
    return



  

options = get_args() #Chamada da função para pegar os parametros

scanned_output = scan(options.ipTarget) #Chamada da função para encontrar os IPs

output_with_datetime = getDateTime(scanned_output) #adiciona os horários de coleta

devices_almostFinal_list = searchManufacturer(output_with_datetime) #adiciona os fabricantes

devices_df = pd.DataFrame(devices_almostFinal_list)


save_data_to_csv(devices_df)
print(devices_df)


