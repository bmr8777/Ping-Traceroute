"""
Name: Brennan Reed <@bmr8777@rit.edu>
Date: 11/5/20
Description: Implementation of the Linux traceroute command in python
"""

import argparse
import math
import random
import select
import socket
import socket_utils
import struct
import time
import sys

PACKET_SIZE = 44
SEQ_NUM = 1
ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp')
ICMP_MAX_REC = 2048
MAX_HOPS = 64
UDP = socket.getprotobyname('udp')


def create_packet(packet_id):
    """
    Create a new echo request packet with the specified id

    @param packet_id: id associated with the created packet
    @return: the created packet
    """

    chksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, chksum, packet_id, 1)
    data = socket_utils.generate_payload(PACKET_SIZE)
    chksum = socket_utils.calculate_checksum(header + data)

    if sys.platform == 'darwin':
        chksum = socket.htons(chksum) & 0xffff
    else:
        chksum = socket.htons(chksum)

    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, chksum, packet_id, 1)

    return header + data


def receive_ping(skt, sending_time, timeout):
    """
    Receive a ping from the socket

    @param skt: socket to receive the ping
    @param sending_time: value of when the ping was sent
    @param timeout: timeout value
    @return: 0 if not successful, else (address of sender, calculated delay)
    """

    time_remaining = timeout

    while True:

        ready = select.select([skt], [], [], time_remaining)

        if not ready[0]:
            return 0

        rec_packet, address = skt.recvfrom(ICMP_MAX_REC)
        time_received = time.time()

        total_time = (time_received - sending_time) * 1000
        total_time = math.ceil(total_time * 1000) / 1000

        return address[0], total_time


def echo_ping(host, ttl):
    """
    Sends an ICMP echo request to the host, and returns the response

    @param host: destination address
    @param ttl: time-to-live value
    @return: 0 if not successful, else: (address of sender, calculated delay)
    """

    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    except socket.gaierror as e:
        if e.errno == 1:
            msg = "ICMP messages can only be sent from processes running as root"
            raise socket.error(msg)
        raise

    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, struct.pack("I", ttl))

    packet_id = int(random.random() * 65535)
    packet = create_packet(packet_id)

    send_socket.sendto(packet, (host, 1))

    send_socket.close()

    rec_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)

    response = receive_ping(rec_socket, time.time(), 1)
    rec_socket.close()

    return response


def echo_probes(host, address, ttl, count, n):
    """
    Sends count probes to the host, and returns the string representation of the responses

    @param host: host name of the destination
    @param address: destination address
    @param ttl: time-to-live value
    @param count: number of probes
    @param n: numerical flag value
    @return: list of probes, string representation, destination_reached, number of probes answered
    """

    probes = []
    probes_answered = 0
    successful_probe = False
    probe_addresses = []
    probe_address = ""
    probe_host = ""

    for x in range(count):
        probe = echo_ping(address, ttl)
        if probe == 0:
            probe_string = '*'
            probe_addr = None
            probe_host = None
        else:
            probe_string = str(probe[1]) + ' ms '
            probe_addr = probe[0]
            probe_addresses.append(probe[0])
            probes_answered += 1
            successful_probe = True
            probe_address = probe[0]

            try:  # Attempt to get the hostname from the address
                probe_host = socket.gethostbyaddr(probe_addr)[0]
            except socket.error:
                probe_host = probe_addr

        probes.append((probe_addr, probe_host, probe_string))

    destination_reached = False
    probe_strings = ""

    for addr, hst, delay in probes:

        if addr == address:
            destination_reached = True

        probe_strings += " " + delay

    if successful_probe:

        if probe_host is None:
            probe_host = probe_address

        if not n:
            result_string = '{0:>2}  {1:} ({2:})'.format(ttl, probe_host, probe_address)
        else:
            result_string = '{0:>2}  {1:}'.format(ttl, probe_address)

    else:
        result_string = '{0:>2}'.format(ttl)

    return probes, result_string + probe_strings, destination_reached, probes_answered


def main():
    """
    Parse the command line arguments and execute the traceroute program
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', action="store_true", default=False, dest="n", required=False)
    parser.add_argument('-q', action="store", type=int, default=3, dest="nqueries", required=False)
    parser.add_argument('-S', action="store_true", default=False, dest="S", required=False)
    parser.add_argument('host', type=str)
    arguments = parser.parse_args()

    n = arguments.n
    probes = arguments.nqueries
    s = arguments.S
    destination = arguments.host

    if "" in destination:
        url = destination
        destination = str(socket.gethostbyname(destination))
    else:
        url = destination

    print('traceroute to {0:} ({1:}), {2:} hops max, {3:} byte packets'.
          format(url, destination, MAX_HOPS, PACKET_SIZE + 8))

    try:

        for ttl in range(1, MAX_HOPS + 1):
            probe_list, string, destination_reached, answered = echo_probes(url, destination, ttl, probes, n)

            if s:
                packet_loss = float(100 - (100 * (answered / probes)))
                print('{0:} ({1:}% loss)'.format(string, packet_loss))
            else:
                print(string)

            if destination_reached:
                break

    except Exception as err:
        print(err)
    except KeyboardInterrupt as err:
        print(err)

    return 0


if __name__ == '__main__':
    main()
