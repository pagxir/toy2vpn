package com.example.android.toyvpn;

public class TunnelDevice {
        public byte[] getConfigure(int tunnel) { return null; }
        public void doHandshake(int tunnel) {};
        public int doLoop(int tunnel, int tunfd) { return 0; };
        public void setSession(String park) {};
        public void setCookies(String park) {};
}
