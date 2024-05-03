from collections import defaultdict

from src.data_models import Connection, Layer4Protocol, TLSConnection


class NetworkMapper:
    def __init__(self):
        self.ips = set()
        self.connections = set()

        self.dns_relations = defaultdict(dict)
        self.tls_connections = set()

    def add_ip(self, ip):
        self.ips.add(ip)

    def add_connection(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: Layer4Protocol):
        connection = Connection(src_ip=src_ip,
                                dst_ip=dst_ip,
                                src_port=src_port,
                                dst_port=dst_port,
                                protocol=protocol)
        self.connections.add(connection)

    def add_tls_connection(self, src_ip: str, dst_domain: str, src_port: int, dst_port: int):
        connection = TLSConnection(src_ip=src_ip,
                                dst_domain=dst_domain,
                                src_port=src_port,
                                dst_port=dst_port,
                                protocol=Layer4Protocol.TCP)
        self.tls_connections.add(connection)

    # TODO: Create a method to add DNS responses as well
    def add_dns_relation(self, peer_address: str, dns_server: str, queries: list):
        if peer_address in self.dns_relations[dns_server]:
            self.dns_relations[dns_server][peer_address].extend(queries)
        else:
            self.dns_relations[dns_server][peer_address] = queries
