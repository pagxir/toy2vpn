#CXXFLAGS=-DUSE_DNS_MODE
LDLIBS=-lrt
COBJECTS=tcpup_toyvpn.o tcpup_ip.o tcpup_up.o tcpup_crypt.o tcpup_contrak.o tcpup_dnstrak.o
SOBJECTS=tcpup_agent.o tcpup_ip.o tcpup_up.o tcpup_crypt.o tcpup_contrak.o tcpup_dnstrak.o

all: toyclient toyserver

toyclient: $(COBJECTS)
	$(CXX) $(COBJECTS) $(LDLIBS) -o toyclient

toyserver: $(SOBJECTS)
	$(CXX) $(SOBJECTS) $(LDLIBS) -o toyserver

.PHONY: clean

clean:
	$(RM) -f $(COBJECTS) ToyVpnClient.o ToyVpnServer.o ToyVpnServer-ping.o
