/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.qifen.toyvpn;

import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.net.InetSocketAddress;

import java.util.List;
import java.util.LinkedList;
import java.util.Iterator;

public class ToyVpnService extends VpnService implements Handler.Callback, Runnable {
    private static final String TAG = "ToyVpnService";

    private String mServerAddress;
    private String mServerPort;
    private String mSharedSecret;
    private PendingIntent mConfigureIntent;

    private Handler mHandler;
    private Thread mThread;

    private ParcelFileDescriptor mInterface;
    private String mParameters;
    private boolean mStarted = false;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // The handler is only used to show messages.
        if (mHandler == null) {
            mHandler = new Handler(this);
        }

        // Stop the previous session by interrupting the thread.
        if (mThread != null) {
            mStarted = false;
            mThread.interrupt();
            try { mThread.join(); } catch (Exception e) {};
            mThread = null;
        }

        // Extract information from the intent.
        String prefix = getPackageName();
        mServerAddress = intent.getStringExtra(prefix + ".ADDRESS");
        mServerPort = intent.getStringExtra(prefix + ".PORT");
        mSharedSecret = intent.getStringExtra(prefix + ".SECRET");

        Log.i(TAG, "config address " + mServerAddress);
        Log.i(TAG, "config port " + mServerPort);
        Log.i(TAG, "config secret " + mSharedSecret);

        // Start a new session by creating a new thread.
        mThread = new Thread(this, "ToyVpnThread");
        mStarted = true;
        mThread.start();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (mThread != null) {
            mStarted = false;
            mThread.interrupt();
            try { mThread.join(); } catch (Exception e) {};
            mStarted = true;
            mThread = null;
        }
    }

    @Override
    public boolean handleMessage(Message message) {
        if (message != null) {
            Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        }
        return true;
    }

    @Override
    public synchronized void run() {
        try {
            Log.i(TAG, "Starting");

            // If anything needs to be obtained using the network, get it now.
            // This greatly reduces the complexity of seamless handover, which
            // tries to recreate the tunnel without shutting down everything.
            // In this demo, all we need to know is the server address.
            InetSocketAddress server = new InetSocketAddress(
                    mServerAddress, Integer.parseInt(mServerPort));

            // We try to create the tunnel for several times. The better way
            // is to work with ConnectivityManager, such as trying only when
            // the network is avaiable. Here we just use a counter to keep
            // things simple.
            for (int attempt = 0; mStarted && attempt < 10; ++attempt) {
                mHandler.sendEmptyMessage(R.string.connecting);

                // Reset the counter if we were connected.
                if (run(server)) {
                    attempt = 0;
                }

                // Sleep for a while. This also checks if we got interrupted.
                if (mStarted)
                    Thread.sleep(3000);
            }
            Log.i(TAG, "Giving up");
        } catch (Exception e) {
            Log.e(TAG, "Got " + e.toString());
			e.printStackTrace();
        } finally {
            try {
                mInterface.close();
            } catch (Exception e) {
                // ignore
            }
            mInterface = null;
            mParameters = null;

            mHandler.sendEmptyMessage(R.string.disconnected);
            Log.i(TAG, "Exiting");
        }
    }

    TunnelDevice tunnelDevice = new PingTunnelDevice();

    private boolean run(InetSocketAddress server) throws Exception {
        boolean connected = false;
        PingTunnel tunnel = null;

        try {
            // Create a DatagramChannel as the VPN tunnel.
            tunnel = PingTunnel.open();
			if (tunnel == null) {
            	mHandler.sendEmptyMessage(R.string.permission_deny);
				return false;
			}

            // Protect the tunnel before connecting to avoid loopback.
            if (!protect(tunnel.getFd())) {
                throw new IllegalStateException("Cannot protect the tunnel");
            }

        	tunnelDevice.setSecret(mSharedSecret);
			tunnelDevice.setServer(server);

            // Authenticate and configure the virtual network interface.
            handshake(tunnel);

            // Now we are connected. Set the flag and show the message.
            connected = true;
            mHandler.sendEmptyMessage(R.string.connected);

            tunnelDevice.doLoop(tunnel.getFd(), mInterface.getFd());

        } catch (InterruptedException e) {
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "Got " + e.toString());
			e.printStackTrace();
        } finally {
            try {
                tunnel.close();
            } catch (Exception e) {
                // ignore
            }
        }

        return connected;
    }

    private void handshake(PingTunnel tunnel) throws Exception {
        // To build a secured tunnel, we should perform mutual authentication
        // and exchange session keys for encryption. To keep things simple in
        // this demo, we just send the shared secret in plaintext and wait
        // for the server to send the parameters.

        // Send the secret several times in case of packet loss.
        for (int i = 0; i < 2; ++i) {
            tunnelDevice.doHandshake(tunnel.getFd());
        }

        byte[] data = tunnelDevice.getConfigure(tunnel.getFd());

        if (data != null) {
            Log.e(TAG, "handshake " + data.length);
            configure(new String(data));
            return;
        }

        Log.e(TAG, "timeout handshake");
        throw new IllegalStateException("Timed out");
    }

    int _net_count = 0;
    int[] _net_pref = new int[256];
    int[] _net_list = new int[256];

    int includeNetwork(int network, int prefix) {
        int i, j = 0;
        int net1, msk1;
        int net0, msk0 = (1<< (32 - prefix)) - 1;

        for (i = 0; i < _net_count; i++) {
            int pref = _net_pref[i];

            if (pref <= prefix) {
                msk1 = (1 << (32 - pref)) - 1;
                net0 = (network & ~msk1);

                if (_net_list[i] == net0) {
                    for (int n = 0; n < _net_count - i; n++) {
                        _net_list[j + n] = _net_list[i + n];
                        _net_pref[j + n] = _net_pref[i + n];
                    }
                    _net_count -= (i - j);
                    return 0;
                }

                _net_list[j] = _net_list[i];
                _net_pref[j] = _net_pref[i];
                j++;
                continue;
            }

            net1 = (_net_list[i] & ~msk0);
            if (net1 == network) {
                continue;
            }

            _net_list[j] = _net_list[i];
            _net_pref[j] = _net_pref[i];
            j++;
        }

        _net_list[j] = (network & 0xffffffff);
        _net_pref[j] = prefix;
        _net_count = ++j;
        return 0;
    }

    int excludeNetwork(int network, int prefix) {
        int i, j = 0;
        int net1, msk1;
        int net0, msk0 = (1<< (32 - prefix)) - 1;

        for (i = 0; i < _net_count; i++) {
            int pref = _net_pref[i];

            System.out.println("pref " + Long.toHexString(pref));
            if (pref <= prefix) {
                msk1 = (1 << (32 - pref)) - 1;
                net0 = (network & ~msk1) & 0xffffffff;

                System.out.println("net0 " + Long.toHexString(net0) + " " + Long.toHexString(_net_list[i]));
                if (_net_list[i] == net0) {
                    net0 = _net_list[i];
                    for (int n = 0; n < _net_count - i - 1; n++) {
                        _net_list[j + n] = _net_list[i + 1 + n];
                        _net_pref[j + n] = _net_pref[i + 1 + n];
                    }
                    _net_count -= (i + 1 - j);

                    for (int k = pref + 1; k <= prefix; k++) {
                        int newnet = network ^ (1 << (32 - k));
                        msk1 = (1 << (32 - k)) - 1;
                        newnet &= 0xffffffff;
                        System.out.println("newnet " + Long.toHexString(newnet));
                        includeNetwork(newnet & ~msk1, (int)k);
                    }

                    return 0;
                }

                _net_list[j] = _net_list[i];
                _net_pref[j] = _net_pref[i];
                j++;
                continue;
            }

            net1 = (_net_list[i] & ~msk0) & 0xffffffff;
            System.out.println("net1 " + Long.toHexString(net1));
            System.out.println("network " + Long.toHexString(network));
            if (net1 == network) {
                continue;
            }

            _net_list[j] = _net_list[i];
            _net_pref[j] = _net_pref[i];
            j++;
        }

        _net_count = j;
        return 0;
    }

    private int getNetworkCode(String networkstr) {
        int i;
        int network = 0;
        String[] parts = networkstr.split("[^0-9]");

        for (i = 0; i < parts.length - 1; i++) {
            network <<= 8;
            network |= Integer.parseInt(parts[i]);
        }

        for (; i < 4; i++) {
            network <<= 8;
        }

        network |= Integer.parseInt(parts[parts.length - 1]);
        return network;
    }

	private void updateRoute(Builder builder, String prebuilt, List<String> include, List<String> exclude) {

        String _include[] = {"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3"};
        String _internal[] = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"};

        String _exclude[] = {"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24"};

        /* prebuilt: NONE INTERNAL EXTERNAL */

        int prefix;
        int network;

        _net_count = 0;
        if (prebuilt.equals("INTERNAL")) {
            for (int i = 0; i < _internal.length; i++) {
                String[] parts = _internal[i].split("/");
                prefix = Integer.parseInt(parts[1]);
                network = getNetworkCode(parts[0]);
                includeNetwork(network, prefix);
            }
        } else if (prebuilt.equals("EXTERNAL")) {
            for (int i = 0; i < _include.length; i++) {
                String[] parts = _include[i].split("/");
                prefix = Integer.parseInt(parts[1]);
                network = getNetworkCode(parts[0]);
                includeNetwork(network, prefix);
            }

            for (int i = 0; i < _exclude.length; i++) {
                String[] parts = _exclude[i].split("/");
                prefix = Integer.parseInt(parts[1]);
                network = getNetworkCode(parts[0]);
                excludeNetwork(network, prefix);
            }
        }

        for (Iterator<String> i = include.iterator(); i.hasNext(); ) {
            String item = i.next();
            String[] parts = item.split("/");
            prefix = Integer.parseInt(parts[1]);
            network = getNetworkCode(parts[0]);
            includeNetwork(network, prefix);
        }

        for (Iterator<String> i = exclude.iterator(); i.hasNext(); ) {
            String item = i.next();
            String[] parts = item.split("/");
            prefix = Integer.parseInt(parts[1]);
            network = getNetworkCode(parts[0]);
            excludeNetwork(network, prefix);
        }

        for (int i = 0; i < _net_count; i++) {
			String ipstr = "";
			int p1, p2, p3, p4;
			p1 = (_net_list[i] >> 24) & 0xff;
			p2 = (_net_list[i] >> 16) & 0xff;
			p3 = (_net_list[i] >> 8) & 0xff;
			p4 = (_net_list[i] >> 0) & 0xff;
			ipstr = String.valueOf(p1) + "." + String.valueOf(p2) + "." + String.valueOf(p3) + "." + String.valueOf(p4);
			Log.i(TAG, "add route: " + ipstr + "/" + _net_pref[i]);
			builder.addRoute(ipstr, _net_pref[i]);
        }
    }

    private void configure(String parameters) throws Exception {
        // If the old interface has exactly the same parameters, use it!
        Log.i(TAG, "configure interface " + parameters);
        if (mInterface != null && parameters.replaceAll(" @.*$", "").equals(mParameters)) {
            Log.i(TAG, "Using the previous interface");
            return;
        }

        // Configure a builder while parsing the parameters.
        Builder builder = new Builder();
		String prebuildNetworks = "NONE";
		List<String> includeNetworks = new LinkedList<String>();
		List<String> excludeNetworks = new LinkedList<String>();
		
        for (String parameter : parameters.split(" ")) {
            String[] fields = parameter.split(",");
            try {
                switch (fields[0].charAt(0)) {
                    case 'm':
                        builder.setMtu(Short.parseShort(fields[1]));
                        break;

                    case 'a':
                        builder.addAddress(fields[1], Integer.parseInt(fields[2]));
                        break;

                    case 'r':
						if (fields[0].length() > 1) {
							switch(fields[0].charAt(1)) {
								case 'I':
									includeNetworks.add(fields[1]);
									break;

								case 'X':
									excludeNetworks.add(fields[1]);
									break;

								case 'L':
									prebuildNetworks = fields[1];
									break;
							}
						} else {
							builder.addRoute(fields[1], Integer.parseInt(fields[2]));
						}
                        break;

                    case 'd':
                        builder.addDnsServer(fields[1]);
                        break;

                    case 's':
                        builder.addSearchDomain(fields[1]);
                        break;

					case 'c':
						tunnelDevice.setCookies(fields[1]);
						break;

					case '@':
						tunnelDevice.setSession(fields[1]);
						break;
                }
				updateRoute(builder, prebuildNetworks, includeNetworks, excludeNetworks);
            } catch (Exception e) {
				e.printStackTrace();
                throw new IllegalArgumentException("Bad parameter: " + parameter);
            }
        }

        // Close the old interface since the parameters have been changed.
        try {
            mInterface.close();
        } catch (Exception e) {
            // ignore
        }

        // Create a new interface using the builder and save the parameters.
        mInterface = builder.setSession(mServerAddress)
                .setConfigureIntent(mConfigureIntent)
                .establish();
        mParameters = parameters.replaceAll(" @.*$", "");
        Log.i(TAG, "New interface: " + parameters);
    }

	public void onRevoke () {
        Log.i(TAG, "onRevoke");

        // Close the old interface since the parameters have been changed.
        try {
            mInterface.close();
        } catch (Exception e) {
            // ignore
        }

        if (mThread != null) {
            mStarted = false;
            mThread.interrupt();
            try {
                mThread.join();
            } catch (Exception e) {};
        }

        stopSelf();
    }
}
