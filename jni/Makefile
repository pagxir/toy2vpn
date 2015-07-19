#CXXFLAGS=-DUSE_DNS_MODE
LDLIBS=-lrt
COBJECTS=tcpup_toyvpn.o tcpup_ip.o tcpup_up.o tcpup_crypt.o tcpup_contrak.o tcpup_dnstrak.o

all: toyclient

toyclient: $(COBJECTS)
	$(CXX) $(COBJECTS) $(LDLIBS) -o toyclient

toyserver.dns: ToyVpnServer.o
	$(CXX) ToyVpnServer.o -o toyserver.dns

toyserver.ping: ToyVpnServer-ping.o
	$(CXX) ToyVpnServer-ping.o -o toyserver.ping

ToyVpnServer-ping.o: ToyVpnServer.cpp
	$(CXX) -c -o ToyVpnServer-ping.o ToyVpnServer.cpp

toyserver: toyserver.dns toyserver.ping

.PHONY: toyserver clean

clean:
	$(RM) -f $(COBJECTS) ToyVpnClient.o ToyVpnServer.o ToyVpnServer-ping.o
