from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re


IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class ReceivedIP:
    address: str
    scope: str


def extract_received_ips(received_headers: list[str]) -> list[ReceivedIP]:
    found_ips: dict[str, ReceivedIP] = {}

    for header in received_headers:
        for match in IPV4_PATTERN.findall(header):
            try:
                ip = ipaddress.ip_address(match)
            except ValueError:
                continue

            address = str(ip)

            if address not in found_ips:
                found_ips[address] = ReceivedIP(
                    address=address,
                    scope=classify_ip(ip),
                )

    return list(found_ips.values())


def classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.is_loopback:
        return "loopback"

    if ip.is_private:
        return "private"

    if ip.is_link_local:
        return "link-local"

    if ip.is_multicast:
        return "multicast"

    if ip.is_reserved:
        return "reserved"

    if ip.is_global:
        return "public"

    return "unknown"