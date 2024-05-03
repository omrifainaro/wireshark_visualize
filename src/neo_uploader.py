from typing import List

from py2neo import Graph, Node, Relationship

from src.data_models import Connection
from src.protocol_utils import protocols


class Neo4jUploader:
    DEFAULT_URI = "bolt://localhost:7687"
    DEFAULT_CREDS = ("neo4j", "12345678")

    def __init__(self, uri, user, password):
        auth = (user, password)
        self.graph = Graph(uri, auth=auth)

    def create_nodes_and_relation_for_connections(self, connections: List[Connection]):
        for connection in connections:
            # Create source IP node
            src_ip_node = Node("IP", address=connection.src_ip)
            self.graph.merge(src_ip_node, "IP", "address")

            # Create destination IP node
            dst_ip_node = Node("IP", address=connection.dst_ip)
            self.graph.merge(dst_ip_node, "IP", "address")

            smaller_port = min(connection.src_port, connection.dst_port)
            protocol = protocols.get(smaller_port, str(smaller_port))
            title = f"CONNECTED_TO_{connection.protocol.value}_{protocol}"
            # Create relation between source and destination IP nodes
            relation = Relationship(src_ip_node,
                                    title,
                                    dst_ip_node,
                                    src_port=connection.src_port,
                                    dst_port=connection.dst_port)
            self.graph.merge(relation)

    def create_dns_relations(self, dns_relations: dict):
        print(dns_relations)
        for dns_server in dns_relations:
            dns_server_node = Node("DNS", address=dns_server)
            self.graph.merge(dns_server_node, "DNS", "address")
            for peer_address in dns_relations[dns_server]:
                peer_node = Node("IP", address=peer_address)
                self.graph.merge(peer_node, "IP", "address")
                queries = dns_relations[dns_server][peer_address]
                queries = "\n".join(queries)
                relation = Relationship(dns_server_node, "DNS_QUERY", peer_node, queries=queries)
                self.graph.merge(relation)

    def create_tls_connections(self, tls_connections: set):
        for connection in tls_connections:
            src_ip_node = Node("IP", address=connection.src_ip)
            self.graph.merge(src_ip_node, "IP", "address")

            dst_domain_node = Node("Domain", address=connection.dst_domain)
            self.graph.merge(dst_domain_node, "Domain", "address")

            relation = Relationship(src_ip_node, "CONNECTED_TO_TLS", dst_domain_node, src_port=connection.src_port,
                                    dst_port=connection.dst_port)
            self.graph.merge(relation)

    def clear_all(self):
        self.graph.delete_all()
