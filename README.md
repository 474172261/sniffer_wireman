A Simple Python Sniffer based on Winpcap with GUI

Usage:
1,pick a file or push "device" button to get devices
2,push "start"
3,if you wanna set a filter
push "apply"

Filter:
key[>,=,<,-]value
key:proto,len,No,info,time,dst,srt

"\-" means include

example:
proto=UDP     :only udp
len>100       :len>100 bytes
info-ACK      :ack=1
dst-192.168.1 :dst like 192.168.1*.*
