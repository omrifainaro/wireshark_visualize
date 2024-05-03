from loguru import logger
from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.tls import handshake
from scapy.layers.tls.record import TLS
from scapy.packet import Packet

from src.data_models import Layer4Protocol
from src.neo_uploader import Neo4jUploader
from src.network_mapper import NetworkMapper


class WiresharkHandler:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.network_mapper = NetworkMapper()

        self._ip_src = None
        self._ip_dst = None
        self._src_port = None
        self._dst_port = None
        self._protocol = None

    def digest_packets(self):
        with PcapReader(self.file_path) as pcap_reader:
            for packet in pcap_reader:
                self._handle_packet(packet)

    def _handle_packet(self, packet: Packet):
        handled = False
        if packet.haslayer("ARP"):
            self.handle_arp(packet)
            handled = True
        if packet.haslayer("IP") or packet.haslayer("IPv6"):
            self.handle_ip(packet, packet.haslayer("IPv6") == 1)
            handled = True
        if packet.haslayer("TCP") or packet.haslayer("UDP"):
            self.handle_layer4(packet, packet.haslayer("UDP") == 1)
            handled = True
        if packet.haslayer("DNS"):
            self.handle_dns(packet)
            handled = True
        if packet.haslayer("HTTP"):
            self.handle_http(packet)
            handled = True
        if packet.haslayer(TLS):  # self._dst_port == 443 or self._src_port == 443:
            self.handle_https(packet)
            handled = True
        if not handled:
            print(f"Unsupported packet type: {packet.summary()}")

    @staticmethod
    def handle_arp(packet: Packet):
        # The ether layer is not very interesting as we are mostly interested in ip level and aboce
        # arp_layer = packet[ARP]
        # if arp_layer.op == 1:
        #     logger.debug(f"Request: Who has {arp_layer.pdst}? Tell {arp_layer.psrc}")
        # elif arp_layer.op == 2:
        #     logger.debug(f"Response: {arp_layer.hwsrc} is at {arp_layer.psrc}")
        # else:
        #     logger.debug(f"Unsupported ARP operation {arp_layer.op}")
        ...

    def handle_ip(self, packet: Packet, is_ipv6: bool):
        layer = packet[IPv6] if is_ipv6 else packet[IP]
        self._ip_src = layer.src
        self._ip_dst = layer.dst
        self.network_mapper.add_ip(self._ip_src)
        self.network_mapper.add_ip(self._ip_dst)

    def handle_layer4(self, packet: Packet, is_udp: bool):
        layer = packet[UDP] if is_udp else packet[TCP]
        self._src_port = layer.sport
        self._dst_port = layer.dport
        self._protocol = Layer4Protocol.UDP if is_udp else Layer4Protocol.TCP
        self.network_mapper.add_connection(self._ip_src,
                                           self._ip_dst,
                                           self._src_port,
                                           self._dst_port,
                                           self._protocol)

    def handle_dns(self, packet: Packet):
        layer = packet["DNS"]
        if layer.qr == 0:
            # logger.debug(f"DNS Request: {layer.qd.qname}")
            queries = [query.qname.decode('utf-8') for query in layer.qd]
            self.network_mapper.add_dns_relation(self._ip_src, self._ip_dst, queries)

    def handle_http(self, packet: Packet):
        ...

    def handle_https(self, packet: Packet):
        layer = packet[TLS]
        if layer.type == 22 and layer.msg and layer.msg[0].msgtype == 1:
            for ext in layer.msg[0].ext:
                if ext.type == 0:  # Fucking scapy
                    server_name = ext.servernames[0].servername.decode('utf-8')
                    # logger.debug(f"HTTPS: {server_name}")
                    self.network_mapper.add_tls_connection(self._ip_src, server_name, self._src_port, self._dst_port)

