package com.example.android.toyvpn;


import android.util.Log;
import java.io.IOException;
import java.io.DataInputStream;
import java.io.DataOutputStream;

public class PingTunnel {
	private int mFd;
	static final String TAG = "PingTunnel";

	private PingTunnel(int fd) {
		mFd = fd;
	}

	static boolean enablePingTunnel() {

		try {
			Process process = Runtime.getRuntime().exec("su");
			DataOutputStream os = new DataOutputStream(process.getOutputStream());
			os.writeBytes("echo 0 2147483647 > /proc/sys/net/ipv4/ping_group_range" + "\n");
			os.writeBytes("exit\n");
			os.flush();
			process.waitFor();
			Log.i(TAG, "exit value = " + process.exitValue());
		} catch (InterruptedException e) {
			return false;
		} catch (IOException e) {
			return false;
		}

		/* Runtime.getRuntime().exec("su -c \"sysctl -w net.ipv4.ping_group_range='0 2147483647'\""); */
		return true;
	}

	public static PingTunnel open() {
		int fd = PingTunnelDevice.do_open();

		if (fd == -1 && enablePingTunnel()) {
			fd = PingTunnelDevice.do_open();
		}

		if (fd == -1) return null;
		return new PingTunnel(fd);
	}

	public int getFd() {
		return mFd;
	}

	public void close() {
		PingTunnelDevice.do_close(mFd);
		mFd = -1;
	}
}

