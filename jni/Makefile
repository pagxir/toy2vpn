#CXXFLAGS=-DUSE_DNS_MODE
LDLIBS=-static -lrt
COBJECTS=tcpup_toyvpn.o tcpup_ip.o tcpup_up.o tcpup_crypt.o tcpup_contrak.o tcpup_dnstrak.o
SOBJECTS=tcpup_agent.o tcpup_ip.o tcpup_up.o tcpup_crypt.o tcpup_contrak.o tcpup_dnstrak.o
TOBJECTS=tcpup_tun2socks.o tcpup_ip.o tcpup_up.o tcpup_crypt.o tcpup_contrak.o tcpup_dnstrak.o

all: toyclient toyserver tun2socks

toyclient: $(COBJECTS)
	$(CXX) $(COBJECTS) $(LDLIBS) -o toyclient

toyserver: $(SOBJECTS)
	$(CXX) $(SOBJECTS) $(LDLIBS) -o toyserver

tun2socks: $(TOBJECTS)
	$(CXX) $(TOBJECTS) $(LDLIBS) -o tun2socks

.PHONY: clean

clean:
	$(RM) -f $(COBJECTS) $(TOBJECTS) $(SOBJECTS)
