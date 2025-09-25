import scapy.all as scapy
import argparse
from mac_vendor_lookup import MacLookup
from datetime import datetime
import pandas as pd
import socket
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', '--ipTarget', dest='ipTarget', help='Target IP Address/Adresses')
    options = parser.parse_args()

    if not options.ipTarget:
        parser.error("[-] Por favor, especifique um IP")
    return options

collectionFirst = datetime.now()

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast_arp_request = broadcast / arp_request
    answered_list = scapy.srp(broadcast_arp_request, timeout=1, verbose=False)[0]
    
    devices_list = []
    for i in range(0, len(answered_list)):
        device_info = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        devices_list.append(device_info)
    
    return devices_list

def check_router_ports(ip, timeout=1):
    router_ports = [22, 23, 53, 80, 161, 443, 8080, 8443]
    open_ports = []
    
    for port in router_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    
    return open_ports

def get_ttl(ip):
    try:
        result = subprocess.run(['ping', '-c', '1', ip], 
                              capture_output=True, text=True, timeout=3)
        ttl_match = re.search(r'ttl=(\d+)', result.stdout.lower())
        if ttl_match:
            return int(ttl_match.group(1))
    except:
        pass
    return None

def analyze_manufacturer_for_router(manufacturer):
    router_vendors = [
        'cisco', 'tp-link', 'netgear', 'linksys', 'asus', 'belkin',
        'd-link', 'huawei', 'zte', 'mikrotik', 'ubiquiti', 'fortinet',
        'juniper', 'aruba', 'alcatel', 'extreme', 'brocade', 'palo alto'
    ]
    
    if manufacturer:
        manufacturer_lower = manufacturer.lower()
        return any(vendor in manufacturer_lower for vendor in router_vendors)
    return False

def classify_device_type(device_info):
    ip = device_info['ip']
    manufacturer = device_info.get('manufacturer', '').lower()
    
    router_score = 0
    
    open_ports = check_router_ports(ip)
    if open_ports:
        router_score += len(open_ports) * 10
        critical_router_ports = [22, 23, 80, 161, 443]
        critical_ports_found = [p for p in open_ports if p in critical_router_ports]
        if critical_ports_found:
            router_score += len(critical_ports_found) * 20
    
    ttl = get_ttl(ip)
    if ttl:
        if ttl in [64, 128, 255]:
            router_score += 15
        device_info['ttl'] = ttl
    
    if analyze_manufacturer_for_router(manufacturer):
        router_score += 25
    
    ip_last_octet = int(ip.split('.')[-1])
    if ip_last_octet in [1, 254]:
        router_score += 30
    
    if router_score >= 50:
        device_type = "Router"
    elif router_score >= 25:
        device_type = "Possible Router"
    else:
        device_type = "Host"
    
    device_info['device_type'] = device_type
    device_info['router_score'] = router_score
    
    return device_info

def classify_all_devices(devices_list):
    with ThreadPoolExecutor(max_workers=10) as executor:
        classified_devices = list(executor.map(classify_device_type, devices_list))
    return classified_devices

def getDateTime(result):
    for i in result:
        i["CollectionFirst"] = collectionFirst.strftime("%Y-%m-%d %H:%M:%S")
    return result

def find_vendor(mac_address):
    mac = MacLookup()
    try:
        result = mac.lookup(mac_address)
    except:
        try:
            mac.update_vendors()
            result = mac.lookup(mac_address)
        except:
            result = "Unknown"
    return result

def searchManufacturer(result):
    for i in result:
        i["manufacturer"] = find_vendor(i["mac"])
    return result

def save_data_to_csv(devices_df):
    try:
        old_df = pd.read_csv(f'discovery.csv')
        df_compare = devices_df[~devices_df['mac'].isin(old_df['mac'])]
        final_df = pd.concat([old_df, df_compare], ignore_index=True)
        final_df.to_csv(f'discovery.csv', index=False)
    except FileNotFoundError:
        devices_df.to_csv(f'discovery.csv', index=False)

options = get_args()
scanned_output = scan(options.ipTarget)
output_with_datetime = getDateTime(scanned_output)
devices_with_manufacturer = searchManufacturer(output_with_datetime)
classified_devices = classify_all_devices(devices_with_manufacturer)
devices_df = pd.DataFrame(classified_devices)
save_data_to_csv(devices_df)
print(devices_df)