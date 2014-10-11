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

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // The handler is only used to show messages.
        if (mHandler == null) {
            mHandler = new Handler(this);
        }

        // Stop the previous session by interrupting the thread.
        if (mThread != null) {
            mThread.interrupt();
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
        mThread.start();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (mThread != null) {
            mThread.interrupt();
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
            for (int attempt = 0; attempt < 10; ++attempt) {
                mHandler.sendEmptyMessage(R.string.connecting);

                // Reset the counter if we were connected.
                if (run(server)) {
                    attempt = 0;
                }

                // Sleep for a while. This also checks if we got interrupted.
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

    private void configure(String parameters) throws Exception {
        // If the old interface has exactly the same parameters, use it!
        Log.i(TAG, "Using the previous interface " + parameters);
        if (mInterface != null && parameters.replaceAll(" @.*$", "").equals(mParameters)) {
            Log.i(TAG, "Using the previous interface");
            return;
        }

        // Configure a builder while parsing the parameters.
        Builder builder = new Builder();
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
                        builder.addRoute(fields[1], Integer.parseInt(fields[2]));
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
            } catch (Exception e) {
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
}
