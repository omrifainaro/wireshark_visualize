from pathlib import Path

from src.neo_uploader import Neo4jUploader
from src.wireshark_handler import WiresharkHandler


def arg_parser():
    import argparse
    parser = argparse.ArgumentParser(description='Scan pcap file and upload to neo4j')
    parser.add_argument('pcap_file', type=str, help='Path to the pcap file')
    parser.add_argument('--clear-all', default=False, type=bool, help='Clear all data from neo4j')
    parser.add_argument('--uri', type=str, default=Neo4jUploader.DEFAULT_URI, help='URI for the Neo4j container')
    parser.add_argument('--username', type=str, default=Neo4jUploader.DEFAULT_CREDS[0],
                        help='Username for the Neo4j container')
    parser.add_argument('--password', type=str, default=Neo4jUploader.DEFAULT_CREDS[1],
                        help='Password for the Neo4j container')
    return parser.parse_args()


def upload(path, clear_all, uri, user, passw):
    uploader = Neo4jUploader(uri, user, passw)
    wireshark_handler = WiresharkHandler(path)
    wireshark_handler.digest_packets()
    if clear_all:
        uploader.clear_all()
    uploader.create_nodes_and_relation_for_connections(wireshark_handler.network_mapper.connections)
    uploader.create_dns_relations(wireshark_handler.network_mapper.dns_relations)
    uploader.create_tls_connections(wireshark_handler.network_mapper.tls_connections)


def main():
    args = arg_parser()
    upload(args.pcap_file, args.clear_all, args.uri, args.username, args.password)


if __name__ == '__main__':
    main()
