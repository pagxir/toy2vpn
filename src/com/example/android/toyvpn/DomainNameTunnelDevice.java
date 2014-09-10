package com.example.android.toyvpn;

import java.net.InetSocketAddress;

public class DomainNameTunnelDevice implements TunnelDevice {
	public byte[] getConfigure(int tunnel) {
		return null;
	}

	public void doHandshake(int tunnel) {
	}

	public int doLoop(int tunnel, int tunfd) {
		return 0;
	}

	public void setSession(String park) {
	}

	public void setCookies(String park) {
	}

	public void setSecret(String key) {
	}

	public void setServer(InetSocketAddress target) {
	}
}
