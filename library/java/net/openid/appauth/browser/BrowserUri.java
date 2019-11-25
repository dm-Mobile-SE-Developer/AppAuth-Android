package net.openid.appauth.browser;

import android.net.Uri;

public class BrowserUri {
    private static final String EXAMPLE_URL = "https://www.example.com";
    public static final Uri CHROME = Uri.parse("googlechrome://" + EXAMPLE_URL);
    public static final Uri SAMSUNG_INTERNET = Uri.parse("samsunginternet://com.sec.android.app.sbrowser://" + EXAMPLE_URL);
    public static final Uri FIREFOX = Uri.parse("firefox://" + EXAMPLE_URL);
    public static final Uri EDGE = Uri.parse("microsoft-edge://" + EXAMPLE_URL);
}
