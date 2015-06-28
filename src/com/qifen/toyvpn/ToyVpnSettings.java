package com.qifen.toyvpn;

import android.app.Dialog;
import android.app.ActionBar;
import android.app.ProgressDialog;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.preference.Preference;
import android.preference.PreferenceActivity;
import android.preference.PreferenceGroup;
import android.preference.PreferenceScreen;
import android.util.Log;
import android.view.Menu;
import android.view.Gravity;
import android.net.VpnService;
import android.view.MenuItem;
import android.widget.Toast;
import android.widget.Button;
import android.widget.Switch;
import android.widget.ListView;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;

import java.util.Scanner;
import java.util.ArrayList;
import java.io.IOException;

import java.net.URL;
import java.net.URLConnection;

public class ToyVpnSettings extends PreferenceActivity
	implements Preference.OnPreferenceChangeListener{

	private static boolean isServiceOn = false;

	private OnCheckedChangeListener mOnChecked = new OnCheckedChangeListener() {
		public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {

			if (isChecked) {
				Intent intent = VpnService.prepare(ToyVpnSettings.this);

				Log.d("ToyVPN", "onClick");
				if (intent != null) {
					startActivityForResult(intent, REQUEST_CONNECT_TOYVPN);
				} else {
					onActivityResult(REQUEST_CONNECT_TOYVPN, RESULT_OK, null);
				}
			} else {
				Intent intent = new Intent(ToyVpnSettings.this, ToyVpnService.class);
				intent.putExtra("TEARDOWN", true);
				startService(intent);
			}

			return;
		}
	};

    @Override
    protected void onCreate(Bundle icicle) {
		super.onCreate(icicle);

		addPreferencesFromResource(R.xml.apn_settings);

		ListView listView = getListView();
		actionBarSwitch = (Switch)getLayoutInflater()
			.inflate(R.layout.actionbar_top, null);

		ActionBar actionBar = getActionBar();
		actionBar.setCustomView(actionBarSwitch);
		actionBar.setDisplayOptions(ActionBar.DISPLAY_SHOW_HOME| ActionBar.DISPLAY_SHOW_CUSTOM);
		actionBar.setCustomView(actionBarSwitch, new ActionBar.LayoutParams(
					ActionBar.LayoutParams.WRAP_CONTENT,
					ActionBar.LayoutParams.WRAP_CONTENT,
					Gravity.CENTER_VERTICAL | Gravity.RIGHT));
	}

	Switch actionBarSwitch = null;

    @Override
    protected void onResume() {
		super.onResume();

		if (ToyVpnService.sState != 0) actionBarSwitch.setChecked(true);
		actionBarSwitch.setOnCheckedChangeListener(mOnChecked);
		fillList();
    }

    private void fillList() {
        PreferenceGroup apnList = (PreferenceGroup) findPreference("apn_list");
        apnList.removeAll();

		SharedPreferences sp = getSharedPreferences("ubn_conf", Context.MODE_PRIVATE);
		String siteList = sp.getString("vpn_site_list", "");

		Resources res = getResources();
		String[] items = res.getStringArray(R.array.vpn_site_list);

		String[] saves = siteList.split("\\|");
		if (saves.length > 1) {
			items = saves;
		}

        for (String item: items) {
            String key = item;
            String[] parts = item.split(":");

            String apn = parts[1];
            String name = parts[0];

            ToyVpnPreference pref = new ToyVpnPreference(this);

            pref.setKey(key);
            pref.setTitle(name);
            pref.setSummary(apn);
            pref.setPersistent(false);
            pref.setOnPreferenceChangeListener(this);

            apnList.addPreference(pref);
        }
    }

    static final int REQUEST_CONNECT_TOYVPN = 0x9128;

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
		if (result == RESULT_OK && request == REQUEST_CONNECT_TOYVPN) {
			String prefix = getPackageName();
			String selectKey = ToyVpnPreference.mSelectedKey;

			if (selectKey != null && !selectKey.equals("")) {
				String[] parts = selectKey.split(":");
				Intent intent = new Intent(this, ToyVpnService.class);
				intent.putExtra(prefix + ".ADDRESS", parts[1]);

				String[] args = parts[2].split(",");
				for (String arg: args) {
					if (arg.equals("UDP")) {
						intent.putExtra(prefix + ".DNSMODE", "UDP");
					} else if (arg.equals("RAW")) {
						intent.putExtra(prefix + ".DNSMODE", "RAW");
					} else {
						String[] valpair = arg.split("=");
						if (valpair.length >= 2) {
							if (valpair[0].equals("port")) {
								intent.putExtra(prefix + ".PORT", valpair[1]);
							} else if (valpair[0].equals("secret")) {
								intent.putExtra(prefix + ".SECRET", valpair[1]);
							}
						}
					}
				}

				startService(intent);
				Log.d("ToyVPN", "onActivityResult " + selectKey);
			}
		}
	}

    @Override
    protected void onPause() {
		actionBarSwitch.setOnCheckedChangeListener(null);
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }

	static final int MENU_RESTORE = 0x90;

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        super.onCreateOptionsMenu(menu);
/*
        menu.add(0, MENU_NEW, 0,
                getResources().getString(R.string.menu_new))
                .setIcon(android.R.drawable.ic_menu_add)
                .setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);
        menu.add(0, MENU_RESTORE, 0,
                getResources().getString(R.string.menu_restore))
                .setIcon(android.R.drawable.ic_menu_upload);
*/
		menu.add(0, MENU_RESTORE, 0,
				getResources().getString(R.string.menu_restore))
			.setIcon(android.R.drawable.ic_menu_upload);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

		switch (item.getItemId()) {
			case MENU_RESTORE:
				new Thread(mUpdateConfig).start();
				break;
		}

        return super.onOptionsItemSelected(item);
    }

    @Override
    public boolean onPreferenceTreeClick(PreferenceScreen preferenceScreen, Preference preference) {
	Log.d("ToyVPN", "onPreferenceTreeClick");
        return true;
    }

    public boolean onPreferenceChange(Preference preference, Object newValue) {
		Log.d("ToyVPN", "onPreferenceChange");
		return true;
	}

	public void doUpdateConfig() {
		String cnf = "";
		String url = "http://www.9zai.net/downloads/upn.conf";

		try {
			URLConnection conn = new URL(url).openConnection();
			Scanner scanner = new Scanner(conn.getInputStream(), "UTF-8");
			cnf = scanner.useDelimiter("\\A").next();
			scanner.close();
		} catch (IOException e) {
			// e.printStack();
			return;
		}

		SharedPreferences sp = getSharedPreferences("ubn_conf", Context.MODE_PRIVATE);
		SharedPreferences.Editor ed = sp.edit();
		ed.putString("vpn_site_list", cnf);
		ed.commit();
	}

	private Runnable mUpdateConfig = new Runnable() {
		public void run() {
			doUpdateConfig();
		}
	};
}

