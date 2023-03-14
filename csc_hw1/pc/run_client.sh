#!/bin/sh
sudo sh ipsec_victim.sh
sudo ./tcp_client 192.168.222.4 2222 -bp 1111
