package com.qifen.toyvpn;

import android.content.ContentUris;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.preference.Preference;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.View.OnClickListener;
import android.widget.CompoundButton;
import android.widget.RadioButton;
import android.widget.RelativeLayout;

public class ToyVpnPreference extends Preference implements
        CompoundButton.OnCheckedChangeListener, OnClickListener {

    public ToyVpnPreference(Context context, AttributeSet attrs, int defStyle) {
        super(context, attrs, defStyle);
    }

    public ToyVpnPreference(Context context, AttributeSet attrs) {
        this(context, attrs, R.attr.apnPreferenceStyle);
    }

    public ToyVpnPreference(Context context) {
        this(context, null);
    }

    public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
        Log.i("ToyVPN", "ID: " + getKey() + " :" + isChecked);

        if (mProtectFromCheckedChange) {
            return;
        }

        if (isChecked) {
            if (mCurrentChecked != null) {
                mCurrentChecked.setChecked(false);
            }
            mCurrentChecked = buttonView;
            mSelectedKey = getKey();
            callChangeListener(mSelectedKey);
        } else {
            mCurrentChecked = null;
            mSelectedKey = null;
        }
    }

    public void onClick(android.view.View v) {
	Log.d("ToyVPN", "ToyVpnPreference.onClick");
    }

    public View getView(View convertView, ViewGroup parent) {
        View view = super.getView(convertView, parent);

        View widget = view.findViewById(R.id.apn_radiobutton);
        if ((widget != null) && widget instanceof RadioButton) {
		RadioButton rb = (RadioButton) widget;
		rb.setOnCheckedChangeListener(this);

		boolean isChecked = getKey().equals(mSelectedKey);
		if (isChecked) {
			mSelectedKey = getKey();
			mCurrentChecked = rb;
		}

		mProtectFromCheckedChange = true;
		rb.setChecked(isChecked);
		mProtectFromCheckedChange = false;
	}

        View textLayout = view.findViewById(R.id.text_layout);
        if ((textLayout != null) && textLayout instanceof RelativeLayout) {
            textLayout.setOnClickListener(this);
        }

        return view;
    }

    public boolean isChecked() {
        return getKey().equals(mSelectedKey);
    }

    public void setChecked() {
        mSelectedKey = getKey();
    }

    public static String mSelectedKey = null;
    private boolean mProtectFromCheckedChange = false;
    private static CompoundButton mCurrentChecked = null;
}

