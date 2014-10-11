package com.qifen.toyvpn;

import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
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
import android.net.VpnService;
import android.view.MenuItem;
import android.widget.Toast;
import android.widget.Button;
import android.widget.ListView;

import java.util.ArrayList;

public class ToyVpnSettings extends PreferenceActivity
	implements Preference.OnPreferenceChangeListener, android.view.View.OnClickListener {

    private Button mButton;

    @Override
    protected void onCreate(Bundle icicle) {
        super.onCreate(icicle);

        addPreferencesFromResource(R.xml.apn_settings);

	ListView listView = getListView();

	mButton = new Button(this);
	mButton.setText(R.string.connect);
	mButton.setOnClickListener(this);

	listView.addFooterView(mButton);
    }

    @Override
    protected void onResume() {
        super.onResume();

	fillList();
    }

    private void fillList() {
        PreferenceGroup apnList = (PreferenceGroup) findPreference("apn_list");
        apnList.removeAll();

	String[] items = new String[] {
		"mianvps,103.242.8.53,53,mianvps",
		"9zai.net,108.61.163.163,53,9zai",
		"crissic,107.150.1.51,53,crissic",
		"klmva,104.143.37.118,53,klmva",
		"bandwagon,104.128.80.141,53,bandwagon"
	};

        for (String item: items) {
            String key = item;
            String[] parts = item.split(",");

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
    public void onClick(android.view.View v) {
        Intent intent = VpnService.prepare(this);

	Log.d("ToyVPN", "onClick");
        if (intent != null) {
            startActivityForResult(intent, REQUEST_CONNECT_TOYVPN);
        } else {
            onActivityResult(REQUEST_CONNECT_TOYVPN, RESULT_OK, null);
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (result == RESULT_OK && request == REQUEST_CONNECT_TOYVPN) {
            String prefix = getPackageName();
            String selectKey = ToyVpnPreference.mSelectedKey;

	    if (selectKey != null && !selectKey.equals("")) {
		    String[] parts = selectKey.split(",");
		    Intent intent = new Intent(this, ToyVpnService.class)
			    .putExtra(prefix + ".ADDRESS", parts[1])
			    .putExtra(prefix + ".PORT", parts[2])
			    .putExtra(prefix + ".SECRET", parts[3]);
		    startService(intent);
		    Log.d("ToyVPN", "onActivityResult " + selectKey);
	    }
        }
    }

    @Override
    protected void onPause() {
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

