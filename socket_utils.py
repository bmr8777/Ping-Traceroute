"""
Name: Brennan Reed <@bmr8777@rit.edu>
Date: 11/11/20
Description: Collection of utility functions for creating, handling,
    sending/receiving icmp headers/packets using raw sockets
"""

import time
from select import select
from struct import unpack, pack
from socket import htons, error
from sys import byteorder

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_MAX_REC = 2048


def calculate_checksum(source):
    """
    Calculate and return the checksum using the source address

    @param source: source address
    @return: the calculated checksum
    """

    count_num = (int(len(source) / 2)) * 2
    count_sum = 0
    count = 0

    while count < count_num:

        if byteorder == "little":  # Check if little-endian
            low_byte = source[count]
            high_byte = source[count + 1]
        else:
            low_byte = source[count + 1]
            high_byte = source[count]

        count_sum += high_byte * 256 + low_byte

        count += 2

    if count_num < len(source):
        low_byte = source[len(source) - 1]
        count_sum += low_byte

    count_sum &= 0xffffffff

    count_sum = (count_sum >> 16) + (count_sum & 0xffff)
    count_sum += (count_sum >> 16)

    chksum = ~count_sum & 0xffff

    answer = htons(chksum)
    return answer


def generate_icmp(p_id, seq_num, pkt_size):
    """
    Generate an ICMP header

    @param p_id: packet id
    @param seq_num: packed sequence number
    @param pkt_size: data size for the packet
    @return: the icmp header
    """

    chksum = 0

    header = pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, p_id, seq_num)

    data = generate_payload(pkt_size)

    chksum = calculate_checksum(header + data)

    header = pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, p_id, seq_num)

    return header


def generate_payload(padding):
    """
    Generate the required bytes to be added to the payload

    @param padding: number of padding bytes
    @return: formatted padding bytes
    """

    padding_bytes = ""
    for x in range(padding):
        padding_bytes += 'Z'

    return bytes(padding_bytes, "utf-8")


def send_ping(skt, destination, p_id, seq_num, pkt_size):
    """
    Try to send a single ping to the destination address

    @param skt: socket to send the ping from
    @param destination: destination address
    @param p_id: packet id
    @param seq_num: packet sequence number
    @param pkt_size: data size for the packet
    @return: time value for when the packet was sent
    """

    header = generate_icmp(p_id, seq_num, pkt_size)

    data = generate_payload(pkt_size)

    pkt = header + data

    try:
        skt.sendto(pkt, (destination, 1))
    except error as err:
        print("Socket Failure (%s)" % (err.args[1]))

    return time.time()


def receive_ping(skt, p_id, timeout, time_sent):
    """
    Receive a ping from the socket

    @param skt: socket to receive the ping with
    @param p_id: packet id
    @param timeout: timeout value
    @param time_sent: time value of when the packet was sent
    @return: receive time, packet size, ip header, packet seq num, packet ttl, sender address
    """

    time_remaining = timeout

    while True:

        skt.setblocking(0)

        ready = select([skt], [], [], time_remaining)

        if not ready[0]:
            return None, 0, 0, 0, 0, None

        rec_packet, address = skt.recvfrom(ICMP_MAX_REC)
        receive_time = time.time()

        ip_header = rec_packet[:20]

        iph_version, iph_type_of_svc, iph_length, iph_id, \
            iph_flags, iph_ttl, iph_protocol, iph_checksum,\
            iph_source, iph_destination = unpack("!BBHHHHBBII", ip_header)

        icmp_header = rec_packet[20:28]
        icmp_type, icmp_code, icmp_checksum, icmp_packet_id, icmp_seq_num = unpack("!BBHHH", icmp_header)

        if icmp_packet_id == p_id:
            data_size = len(rec_packet) - 28
            return receive_time, (data_size + 8), iph_source, icmp_seq_num, iph_ttl, address

        time_remaining -= receive_time - time_sent

        if time_remaining <= 0:
            return None, 0, 0, 0, 0, None
