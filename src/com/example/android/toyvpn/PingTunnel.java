package com.example.android.toyvpn;

public class PingTunnel {
	public static native PingTunnel open();
	public native int getFd();
	public native void close();
}

