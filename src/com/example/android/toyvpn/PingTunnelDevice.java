package com.example.android.toyvpn;

import java.net.InetSocketAddress;

public class PingTunnelDevice implements TunnelDevice {
	static native void do_handshake(int tunnel);
	static native byte[] get_configure(int tunnel);
	static native int  do_loop(int tunnel, int tunfd);
	static native void set_session(String park);
	static native void set_cookies(String park);
	static native void set_secret(String key);
	static native void set_server(byte[] ipv4);

	static native int do_close(int fd);
	static native int do_open();

	public byte[] getConfigure(int tunnel) {
		return get_configure(tunnel);
	}

	public void doHandshake(int tunnel) {
		do_handshake(tunnel);
	}

	public int doLoop(int tunnel, int tunfd) {
		return do_loop(tunnel, tunfd);
	}

	public void setSession(String park) {
		set_session(park);
	}

	public void setCookies(String park) {
		set_cookies(park);
	}

	public void setSecret(String key) {
		set_secret(key);
	}

	public void setServer(InetSocketAddress target) {
		set_server(target.getAddress().getAddress());
	}

	static {
		System.loadLibrary("pingle");
	}
}
