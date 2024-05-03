from enum import StrEnum

from pydantic import BaseModel


class Layer4Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class Connection(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Layer4Protocol

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))


class TLSConnection(BaseModel):
    src_ip: str
    dst_domain: str
    src_port: int
    dst_port: int

    def __hash__(self):
        return hash((self.src_ip, self.dst_domain, self.src_port, self.dst_port))
