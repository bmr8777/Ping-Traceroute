# Ping-Traceroute
  Python implementation of Linux Ping and Traceroute commands


## Contributers
  Brennan Reed <bmr8777@rit.edu>


## Execution Requirements
    - Python version: 3.6.x
    - socket_utils.py


## Usage
  python3 ping.py [-c count] [-i wait] [-s packetsize] [-t timeout] destination

## Required Arguments
    destination:
        destination address for the ping requests

## Optional Arguments
    -c count:
        count: number of pings to send
    -i wait:
        wait: time to wait between ping requests
    -s packetsize:
        packetsize: number of data bytes to be sent
    -t timeout:
        timeout: the timeout, in seconds

## Example Usage
    ❯ sudo python3 ping.py "google.com"
    ❯ sudo python3 ping.py -c 5 "google.com"
    ❯ sudo python3 ping.py -c 5 -i 2 -s 48 -t 4 "google.com"

## NOTE
  program makes use of raw sockets, and therefore must be ran as root user

## Traceroute Usage
  python3 traceroute.py [-n] [-q nqueries] [-S] destination

## Required Arguments
    destination:
        destination address for the traceroute command

## Optional Arguments
    -n:
        print the hop addresses numerically rather than symbolically and numerically
    -q nqueries:
        nqueries: number of probes per ttl
    -S:
        print a summary of how many probes were not answered for each hop

## Example Usage
    ❯ sudo python3 traceroute.py "google.com"
    ❯ sudo python3 traceroute.py -q 1 "google.com"
    ❯ sudo python3 traceroute.py -q 2 -S -n "1.1.1.1"
