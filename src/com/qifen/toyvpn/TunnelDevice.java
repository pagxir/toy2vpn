package com.qifen.toyvpn;

import java.net.InetSocketAddress;

public interface TunnelDevice {
        public byte[] getConfigure(int tunnel);
        public void doHandshake(int tunnel);
        public int doLoop(int tunnel, int udpfd, int tunfd);
        public void setSession(String park);
		public void setCookies(String park);
		public void setSecret(String key);
		public void setServer(InetSocketAddress target);
}
