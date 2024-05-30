import base64
from pathlib import Path

from scapy.layers.http import HTTPResponse
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import rdpcap

from core.analyzer.base import BaseAnalyzer


MAC_ADDRESSES = ''


class NetworkUtilsService:

    @staticmethod
    def is_private_ip(ip_address: str):
        if ip_address.startswith('127.0.0.'):
            return True
        if ip_address.startswith('10.'):
            return True
        if ip_address.startswith('172.1') or ip_address.startswith('172.2') or ip_address.startswith('172.3'):
            return True
        if ip_address.startswith('192.168.'):
            return True

        return False

    @staticmethod
    def is_public_ip(ip_address: str):
        return not NetworkUtilsService.is_private_ip(ip_address)

    @staticmethod
    def get_suspicious_ip_list():
        return [
            '103.251.167.20',
            '104.192.3.74',
            '107.1.241.169',
            '109.70.100.6',
            '109.70.100.70',
            '12.23.16.117',
            '12.237.159.13',
            '136.158.8.40',
            '136.35.64.112',
            '142.79.75.74',
            '150.221.171.57',
            '178.20.55.16',
            '184.81.56.182',
            '185.181.61.115',
            '185.220.100.251',
            '185.220.102.252',
            '185.220.103.114',
            '185.233.100.23',
            '185.243.218.204',
            '192.42.116.175',
            '192.42.116.180',
            '192.42.116.181',
            '192.42.116.182',
            '192.42.116.183',
            '192.42.116.185',
            '192.42.116.186',
            '192.42.116.187',
            '192.42.116.188',
            '192.42.116.191',
            '192.42.116.193',
            '192.42.116.216',
            '192.42.116.218',
            '195.176.3.20',
            '198.96.155.3',
            '209.163.98.28',
            '23.137.251.61',
            '35.142.132.202',
            '38.97.116.244',
            '45.134.225.36',
            '45.141.215.21',
            '47.147.249.100',
            '47.36.117.128',
            '67.197.64.67',
            '69.162.231.243',
            '69.245.177.224',
            '71.15.71.18',
            '71.239.208.188',
            '71.80.114.24',
            '73.95.1.137',
            '76.198.90.121',
            '76.34.17.67',
        ]

    @staticmethod
    def is_authorized_mac_oui(mac_address: str):
        global MAC_ADDRESSES

        if not MAC_ADDRESSES:
            path = (Path(__file__).parent / 'mac-vendor.txt').resolve().as_posix()
            with open(path, 'r') as f:
                MAC_ADDRESSES = f.read()

        return mac_address in MAC_ADDRESSES


class NetworkAnalyzer(BaseAnalyzer):

    def analyze(self, pcap_file_path: str):
        packets = rdpcap(pcap_file_path)

        stats = []

        for pkt in packets:
            pkt_data = {}

            ether_data = self._load_link_lvl(pkt)
            if not ether_data:
                # Битый пакет - пропускаем
                continue

            network_data = self._load_network_lvl(pkt)
            transport_data = self._load_transport_lvl(pkt)
            application_data = self._load_application_lvl(pkt)

            has_payload = bool(application_data.get('payload'))
            if has_payload:
                application_data.pop('payload')

            pkt_data.update(ether_data)
            pkt_data.update(network_data)
            pkt_data.update(transport_data)
            pkt_data.update(application_data)

            pkt_data.update({
                'packet_length': len(pkt),
                'has_file_payload': has_payload,
            })

            stats.append(pkt_data)

        return stats

    def _load_link_lvl(self, pkt: Packet) -> dict:
        link_lvl_data = {}

        if Ether in pkt:
            ether_pkt = pkt[Ether]
            link_lvl_data.update(dict(
                ether_src=NetworkUtilsService.is_authorized_mac_oui(str(ether_pkt.src)[:8]),
                ether_dst=NetworkUtilsService.is_authorized_mac_oui(str(ether_pkt.dst)[:8]),
            ))

        return link_lvl_data

    def _load_network_lvl(self, pkt: Packet) -> dict:
        network_lvl_data = {}

        if IP in pkt:
            ip_pkt = pkt[IP]
            network_lvl_data.update(dict(
                version=ip_pkt.version,
                ihl=ip_pkt.ihl,
                tos=ip_pkt.tos,
                len=ip_pkt.len,
                id=ip_pkt.id,
                frag=ip_pkt.frag,
                ttl=ip_pkt.ttl,
                proto=ip_pkt.proto,
                chksum=ip_pkt.chksum,
                is_src_ip_private=NetworkUtilsService.is_private_ip(str(ip_pkt.src)),
                is_dest_ip_private=NetworkUtilsService.is_private_ip(str(ip_pkt.dst)),
            ))

        return network_lvl_data

    def _load_transport_lvl(self, pkt: Packet) -> dict:
        transport_lvl_data = {}

        if TCP in pkt:
            tcp_pkt = pkt[TCP]
            transport_lvl_data.update(dict(
                src_port=tcp_pkt.sport,
                dest_port=tcp_pkt.dport,
                seq=tcp_pkt.seq,
                ack=tcp_pkt.ack,
                dataofs=tcp_pkt.dataofs,
                reserved=tcp_pkt.reserved,
                window=tcp_pkt.window,
                tcp_chksum=tcp_pkt.chksum,
                urgptr=tcp_pkt.urgptr,
            ))
        elif UDP in pkt:
            udp_pkt = pkt[UDP]
            transport_lvl_data.update(dict(
                src_port=udp_pkt.sport,
                dest_port=udp_pkt.dport,
                udp_len=udp_pkt.len,
                udp_chksum=udp_pkt.chksum,
            ))

        return transport_lvl_data

    def _load_application_lvl(self, pkt: Packet) -> dict:
        application_lvl_data = {}

        if Raw in pkt and HTTPResponse in pkt:
            payload = pkt[HTTPResponse].load
            application_lvl_data['payload'] = base64.b64encode(payload)

        return application_lvl_data
