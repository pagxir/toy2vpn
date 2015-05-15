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
import android.content.IntentFilter;
import android.content.BroadcastReceiver;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.net.NetworkInfo;
import android.os.Handler;
import android.os.Message;
import android.os.PowerManager;
import android.net.TrafficStats;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.provider.Settings;
import android.util.Log;
import android.widget.Toast;
import android.content.IntentFilter;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.channels.DatagramChannel;
import java.net.InetSocketAddress;

import java.util.List;
import java.util.LinkedList;
import java.util.Iterator;

public class ToyVpnService extends VpnService implements Handler.Callback, Runnable {
    private static final String TAG = "ToyVpnService";

    private String mDnsMode;
    private String mServerAddress;
    private String mServerPort;
    private String mSharedSecret;
    private PendingIntent mConfigureIntent;

    private Thread mThread;
    private Handler mHandler;

    private String mParameters;
    private boolean mStarted = false;
    private ParcelFileDescriptor mInterface = null;

	public static int sState = 0;
	static final int EVENT_SHOW_MESSAGE = 0x01;
	static final int EVENT_DATA_STALL_AVOID = 0x02;
	protected static final String INTENT_DATA_STALL_ALARM =
		"com.android.internal.telephony.data-stall";

	public boolean reConf = false;
	public boolean isConnected = true;
	public boolean isScreenOn  = false;

	public BroadcastReceiver mNetworkMonitor = new BroadcastReceiver() {
		@Override   
		public void onReceive(Context context, Intent intent) {   
            int type;
            ConnectivityManager manager;
			String action = intent.getAction();

			if (action.equals(INTENT_DATA_STALL_ALARM)) {
				Message msg = mHandler.obtainMessage(EVENT_DATA_STALL_AVOID, 0, 0);
				mHandler.sendMessageDelayed(msg, 2000);
			} else if (action.equals(ConnectivityManager.CONNECTIVITY_ACTION)) {
				manager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);   
				NetworkInfo info = manager.getActiveNetworkInfo();
				if (info == null) {
					Log.i(TAG, "Network State Change: no Active Network");
					isConnected = false;
					return;
				}

				type = info.getType();
				if (type == ConnectivityManager.TYPE_WIFI ||
						type == ConnectivityManager.TYPE_MOBILE) {
					Log.i(TAG, "NSType: " + type + "NState: " + info.getState());
					synchronized(mNetworkMonitor) {
						isConnected = true;
						mNetworkMonitor.notifyAll();
					}
				}
			}
		}
	};

	@Override
	public void onCreate( ) {
		IntentFilter filter = new IntentFilter();
		filter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
		filter.addAction(INTENT_DATA_STALL_ALARM);
		registerReceiver(mNetworkMonitor, filter);
	}

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Extract information from the intent.
        String prefix = getPackageName();
        if (intent == null) return 0;
        mDnsMode = intent.getStringExtra(prefix + ".DNSMODE");
        mServerAddress = intent.getStringExtra(prefix + ".ADDRESS");
        mServerPort = intent.getStringExtra(prefix + ".PORT");
        mSharedSecret = intent.getStringExtra(prefix + ".SECRET");

		if (intent.getBooleanExtra("TEARDOWN", false) && mThread != null) {
            mStarted = false;
			if (runTunnel != null) runTunnel.close();
            mThread.interrupt();
            mThread = null;
			return START_STICKY;
		}

        Log.i(TAG, "config address " + mServerAddress);
        Log.i(TAG, "config port " + mServerPort);
        Log.i(TAG, "config secret " + mSharedSecret);
        Log.i(TAG, "config dnsmode " + mDnsMode);

		if (sState == -1) {
			reConf = true;
			return START_STICKY;
		}

        if (mHandler == null) {
            mHandler = new Handler(this);
        }

        if (mThread != null) {
            mStarted = false;
            mThread.interrupt();
            try { mThread.join(); } catch (Exception e) {};
            mThread = null;
        }

        // Start a new session by creating a new thread.
        mThread = new Thread(this, "ToyVpnThread");
        mStarted = true;
        mThread.start();

        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        unregisterReceiver(mNetworkMonitor);
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

        switch (message.what) {
            case EVENT_DATA_STALL_AVOID:
                doDataStallAvoid(this);
                break;

            case EVENT_SHOW_MESSAGE:
                Toast.makeText(this, message.arg2, Toast.LENGTH_SHORT).show();
                break;
        }

        return true;
    }

	public int getRecoveryAction() {
		int action = Settings.System.getInt(this.getContentResolver(),
				"radio.data.stall.recovery.action", 0);
		Log.d(TAG, "getRecoveryAction: " + action);
		return action;
	}

	private Runnable mDataStallAvoid = new Runnable() {
		@Override
		public void run() {
			try {
				SocketChannel socketChannel = SocketChannel.open();
				socketChannel.configureBlocking(false);
				if (!protect(socketChannel.socket())) throw new IllegalStateException("protect data stall tcp socket failure");
				//socketChannel.connect(new InetSocketAddress("www.baidu.com", 80));
				socketChannel.connect(new InetSocketAddress("115.239.210.25", 80));
				socketChannel.close();
			} catch (Exception e) {
				Log.d(TAG, "doDataStallAvoid failure ");
				e.printStackTrace();
				throw new RuntimeException(e);
			}
			return;
		}
	};

	private void doDataStallAvoid(Context context) {
		ConnectivityManager manager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);   

		if (getRecoveryAction() != 0 && sState == 2) {
			NetworkInfo info = manager.getActiveNetworkInfo();
			if (info != null && info.isConnected() &&
				info.getType() == ConnectivityManager.TYPE_MOBILE) {
				new Thread(mDataStallAvoid).start();
			}
		}
	}

    @Override
    public synchronized void run() {
        try {
            Log.i(TAG, "Starting");
            ConnectivityManager manager;
            int port = mServerPort == null? 0: Integer.parseInt(mServerPort);
            InetSocketAddress server = new InetSocketAddress(mServerAddress, port);

            for (int attempt = 0; mStarted && attempt < 4; ++attempt) {
				Message msg = mHandler.obtainMessage(EVENT_SHOW_MESSAGE, 0x00, R.string.connecting);
                mHandler.sendMessage(msg);

                if (run(server)) {
                    attempt = 0;
                }

                synchronized(mNetworkMonitor) {
                    if (attempt > 0) {
                        manager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                        NetworkInfo info = manager.getActiveNetworkInfo();
                        if (isConnected && info == null) isConnected = false;
                    }

                    while (mStarted && !isConnected) {
                        try {
                            mNetworkMonitor.wait();
                            break;
                        } catch (InterruptedException e) {
                            /* ignore */
                        }
                    }
                }

                if (!mStarted) {
                    break;
                }

                if (attempt > 0 && mInterface == null) {
                    Thread.sleep(100);
                    server = new InetSocketAddress(mServerAddress, port);
                }
            }

            Log.i(TAG, "Giving up");
        } catch (Exception e) {
            Log.e(TAG, "Got " + e.toString());
			e.printStackTrace();
        } finally {
            try {
                if (mInterface != null)
					mInterface.close();
            } catch (Exception e) {
                // ignore
            }
            mInterface = null;
            mParameters = null;
			sState = 0;

			Message msg = mHandler.obtainMessage(EVENT_SHOW_MESSAGE, 0x00, R.string.disconnected);
			mHandler.sendMessage(msg);
            Log.i(TAG, "Exiting");
        }
    }

	PingTunnel runTunnel = null;
    TunnelDevice tunnelDevice = new PingTunnelDevice();

    private boolean run(InetSocketAddress server) throws Exception {
        boolean connected = false;
        PingTunnel tunnel = null;

        try {
            tunnel = PingTunnel.open(mDnsMode);
			if (tunnel == null) {
				Message msg = mHandler.obtainMessage(EVENT_SHOW_MESSAGE, 0x00, R.string.permission_deny);
				mHandler.sendMessage(msg);
				return false;
			}

            if (!protect(tunnel.getFd())) {
                throw new IllegalStateException("Cannot protect the tunnel");
            }

            if (!protect(tunnel.getUdpFd())) {
                throw new IllegalStateException("Cannot protect the tunnel");
            }

        	tunnelDevice.setSecret(mSharedSecret);
			tunnelDevice.setServer(server);

            handshake(tunnel);

            connected = true;
			Message msg = mHandler.obtainMessage(EVENT_SHOW_MESSAGE, 0x00, R.string.connected);
			mHandler.sendMessage(msg);
			if (!reConf) {
				runTunnel = tunnel;
				tunnelDevice.doLoop(tunnel.getFd(), tunnel.getUdpFd(), mInterface.getFd());
				runTunnel = null;
			}
			reConf = false;

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

        //String _exclude[] = {"0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24"};
        String _exclude[] = {"0.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16", "169.254.0.0/16"};

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
			Log.d(TAG, "add route: " + ipstr + "/" + _net_pref[i]);
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
			if (fields.length < 1 || fields[0].length() < 1) {
            	Log.i(TAG, "parse failure");
                throw new IllegalArgumentException("Bad parameter: " + parameter);
			}

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
        	Log.i(TAG, "Closing interface.");
			if (mInterface != null) mInterface.close();
        	Log.i(TAG, "Closed interface.");
        } catch (Exception e) {
        	Log.i(TAG, "Closed interface.");
            // ignore
        }

		sState = -1;
        // Create a new interface using the builder and save the parameters.
        mInterface = builder.setSession(mServerAddress + ":" + mDnsMode)
                .setConfigureIntent(mConfigureIntent)
                .establish();
		sState = 2;
        mParameters = parameters.replaceAll(" @.*$", "");
        Log.i(TAG, "New interface: " + parameters);
    }

	public void onRevoke () {
        Log.i(TAG, "onRevoke");

        // Close the old interface since the parameters have been changed.
        try {
			if (mInterface != null) {
            	mInterface.close();
				mInterface = null;
			}
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
