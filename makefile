all: arp_spoofing

arp_spoofing: main.o mac.o ip.o ethhdr.o arphdr.o
	g++ -o arp_spoofing main.o mac.o ip.o ethhdr.o arphdr.o -lpcap
main.o: main.cpp mac.h ip.h ethhdr.h arphdr.h	iphdr.h
	g++ -c -o main1.o main1.cpp

mac.o: mac.cpp mac.h
	g++ -c -o  mac.o mac.cpp
ip.o: ip.cpp ip.h
	g++ -c -o ip.o ip.cpp

ethhdr.o: ethhdr.cpp ethhdr.h
	g++ -c -o ethhdr.o ethhdr.cpp
arphdr.o: arphdr.cpp arphdr.h
	g++ -c -o arphdr.o arphdr.cpp


clean:
	rm -f arp_spoofing
	rm -f *.o

