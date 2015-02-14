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

import java.util.ArrayList;

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

	static final String mSiteList = 
		"Los Angeles(RAW):www.9zai.net:RAW,secret=hello|" +
		"Los Angeles(UDP):www.9zai.net:UDP,port=53,secret=hello|" +
		"Los Angeles(RAW):lax.shifenwa.com:RAW,secret=hello|" +
		"Los Angeles(UDP):lax.shifenwa.com:UDP,port=53,secret=hello|" +
		"tokyo(breakwall only, UDP):tokyo.shifenwa.com:UDP,port=503,secret=hello";

    private void fillList() {
        PreferenceGroup apnList = (PreferenceGroup) findPreference("apn_list");
        apnList.removeAll();

		SharedPreferences sp = getSharedPreferences("world_site_list", Context.MODE_PRIVATE);
		String siteList = sp.getString("site_list", mSiteList);

		String[] items = siteList.split("\\|");

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
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
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
}

