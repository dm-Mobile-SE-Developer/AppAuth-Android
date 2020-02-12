/*
 * Copyright 2015 The AppAuth for Android Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.openid.appauth.browser;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Build.VERSION_CODES;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import androidx.browser.customtabs.CustomTabsService;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Utility class to obtain the browser package name to be used for
 * {@link net.openid.appauth.AuthorizationService#performAuthorizationRequest(
 * net.openid.appauth.AuthorizationRequest,
 * android.app.PendingIntent)} calls. It prioritizes browsers which support
 * [custom tabs](https://developer.chrome.com/multidevice/android/customtabs). To mitigate
 * man-in-the-middle attacks by malicious apps pretending to be browsers for the specific URI we
 * query, only those which are registered as a handler for _all_ HTTP and HTTPS URIs will be
 * used.
 */
public final class BrowserSelector {

    private static final String SCHEME_HTTP = "http";
    private static final String SCHEME_HTTPS = "https";

    /**
     * The service we expect to find on a web browser that indicates it supports custom tabs.
     */
    @VisibleForTesting
    static final String ACTION_CUSTOM_TABS_CONNECTION =
        CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION;

    /**
     * An arbitrary (but unregistrable, per
     * <a href="https://www.iana.org/domains/reserved">IANA rules</a>) web intent used to query
     * for installed web browsers on the system.
     */
    @VisibleForTesting
    static final Intent BROWSER_INTENT = new Intent(
        Intent.ACTION_VIEW,
        Uri.parse("http://www.example.com"));

    /**
     * Retrieves the full list of browsers installed on the device. Two entries will exist
     * for each browser that supports custom tabs, with the {@link BrowserDescriptor#useCustomTab}
     * flag set to `true` in one and `false` in the other. The list is in the
     * order returned by the package manager, so indirectly reflects the user's preferences
     * (i.e. their default browser, if set, should be the first entry in the list).
     */
    @SuppressLint("PackageManagerGetSignatures")
    @NonNull
    public static List<BrowserDescriptor> getAllBrowsers(Context context) {
        PackageManager pm = context.getPackageManager();
        List<BrowserDescriptor> browsers = new ArrayList<>();
        String defaultBrowserPackage = null;

        int queryFlag = PackageManager.GET_RESOLVED_FILTER;
        if (VERSION.SDK_INT >= VERSION_CODES.M) {
            queryFlag |= PackageManager.MATCH_ALL;
        }
        // When requesting all matching activities for an intent from the package manager,
        // the user's preferred browser is not guaranteed to be at the head of this list.
        // Therefore, the preferred browser must be separately determined and the resultant
        // list of browsers reordered to restored this desired property.
        ResolveInfo resolvedDefaultActivity =
            pm.resolveActivity(BROWSER_INTENT, 0);
        if (resolvedDefaultActivity != null) {
            defaultBrowserPackage = resolvedDefaultActivity.activityInfo.packageName;
        }
        List<ResolveInfo> resolvedActivityList =
            pm.queryIntentActivities(BROWSER_INTENT, queryFlag);

        ArrayList<String> resolvedPackageNames = new ArrayList<>();
        for (ResolveInfo resolveInfo : resolvedActivityList) {
            resolvedPackageNames.add(resolveInfo.activityInfo.packageName);
        }

        // This workaround is needed because on some older devices no browsers will be found if the opera (or opera beta) browser is set as default browser.
        if (resolvedPackageNames.size() == 1 && (resolvedPackageNames.contains("com.opera.browser") || resolvedPackageNames.contains("com.opera.browser.beta")) ||
            resolvedPackageNames.size() == 2 && resolvedPackageNames.contains("com.opera.browser") && resolvedPackageNames.contains("com.opera.browser.beta")) {

            // Chrome Beta, Firefox Klar and some other browsers can't be used because of missing custom intent filters (like "googlechrome://...")
            // Ecosia and Brave are listening for "googlechrome://" scheme
            if (isPackageInstalled("com.android.chrome", pm) || isPackageInstalled("com.google.android.apps.chrome", pm)
                || isPackageInstalled("com.ecosia.android", pm) || isPackageInstalled("com.brave.browser", pm)) {
                List<ResolveInfo> resolveInfos = getResolveInfoListForBrowser(BrowserUri.CHROME, pm, queryFlag);
                resolvedActivityList.addAll(resolveInfos);
            }
            if (isPackageInstalled("com.sec.android.app.sbrowser", pm)) {
                List<ResolveInfo> resolveInfos = getResolveInfoListForBrowser(BrowserUri.SAMSUNG_INTERNET, pm, queryFlag);
                resolvedActivityList.addAll(resolveInfos);
            }
            if (isPackageInstalled("org.mozilla.firefox", pm)) {
                List<ResolveInfo> resolveInfos = getResolveInfoListForBrowser(BrowserUri.FIREFOX, pm, queryFlag);
                resolvedActivityList.addAll(resolveInfos);
            }
            if (isPackageInstalled("com.microsoft.emmx", pm)) {
                List<ResolveInfo> resolveInfos = getResolveInfoListForBrowser(BrowserUri.EDGE, pm, queryFlag);
                resolvedActivityList.addAll(resolveInfos);
            }
        }

        for (ResolveInfo info : resolvedActivityList) {
            // ignore handlers which are not browsers
            if (!isFullBrowser(info)) {
                continue;
            }

            String packageName = info.activityInfo.packageName;

            // ignore Firefox Preview (Fenix) and Firefox Klar because they are both not OAuth compatible at the moment
            // https://github.com/mozilla-mobile/fenix/issues/7691
            if (packageName.equals("org.mozilla.fenix") || packageName.equals("org.mozilla.klar")) {
                continue;
            }

            try {
                int defaultBrowserIndex = 0;
                PackageInfo packageInfo = pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES);

                if (hasWarmupService(pm, packageName)) {
                    BrowserDescriptor customTabBrowserDescriptor =
                        new BrowserDescriptor(packageInfo, true);
                    if (packageName.equals(defaultBrowserPackage)) {
                        // If the default browser is having a WarmupService,
                        // will it be added to the beginning of the list.
                        browsers.add(defaultBrowserIndex, customTabBrowserDescriptor);
                        defaultBrowserIndex++;
                    } else {
                        browsers.add(customTabBrowserDescriptor);
                    }
                }

                BrowserDescriptor fullBrowserDescriptor =
                    new BrowserDescriptor(packageInfo, false);
                if (packageName.equals(defaultBrowserPackage)) {
                    // The default browser is added to the beginning of the list.
                    // If there is support for Custom Tabs, will the one disabling Custom Tabs
                    // be added as the second entry.
                    browsers.add(defaultBrowserIndex, fullBrowserDescriptor);
                } else {
                    browsers.add(fullBrowserDescriptor);
                }
            } catch (NameNotFoundException e) {
                // a descriptor cannot be generated without the package info
            }
        }

        return browsers;
    }

    private static List<ResolveInfo> getResolveInfoListForBrowser(Uri browserUri, PackageManager packageManager, int queryFlag) {
        Intent browserIntent = new Intent(Intent.ACTION_VIEW, browserUri);
        return packageManager.queryIntentActivities(browserIntent, queryFlag);
    }

    private static boolean isPackageInstalled(String packageName, PackageManager packageManager) {
        try {
            packageManager.getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    /**
     * Searches through all browsers for the best match based on the supplied browser matcher.
     * Custom tab supporting browsers are preferred, if the matcher permits them, and browsers
     * are evaluated in the order returned by the package manager, which should indirectly match
     * the user's preferences.
     *
     * @param context {@link Context} to use for accessing {@link PackageManager}.
     * @return The package name recommended to use for connecting to custom tabs related components.
     */
    @SuppressLint("PackageManagerGetSignatures")
    @Nullable
    public static BrowserDescriptor select(Context context, BrowserMatcher browserMatcher) {
        List<BrowserDescriptor> allBrowsers = getAllBrowsers(context);
        BrowserDescriptor bestMatch = null;
        for (BrowserDescriptor browser : allBrowsers) {
            if (!browserMatcher.matches(browser)) {
                continue;
            }

            if (browser.useCustomTab) {
                // directly return the first custom tab supporting browser that is matched
                return browser;
            }

            if (bestMatch == null) {
                // store this as the best match for use if we don't find any matching
                // custom tab supporting browsers
                bestMatch = browser;
            }
        }

        return bestMatch;
    }

    private static boolean hasWarmupService(PackageManager pm, String packageName) {
        Intent serviceIntent = new Intent();
        serviceIntent.setAction(ACTION_CUSTOM_TABS_CONNECTION);
        serviceIntent.setPackage(packageName);
        return (pm.resolveService(serviceIntent, 0) != null);
    }

    private static boolean isFullBrowser(ResolveInfo resolveInfo) {
        // The filter must match ACTION_VIEW, CATEGORY_BROWSEABLE, and at least one scheme,
        if (!resolveInfo.filter.hasAction(Intent.ACTION_VIEW)
            || !resolveInfo.filter.hasCategory(Intent.CATEGORY_BROWSABLE)
            || resolveInfo.filter.schemesIterator() == null) {
            return false;
        }

        // This is needed, because the resolveInfo of the Samsung Internet browser doesn't contain the "http" or "https" scheme
        IntentFilter intentFilter = resolveInfo.filter;
        if (intentFilter != null && intentFilter.countDataAuthorities() > 0) {
            IntentFilter.AuthorityEntry authorityEntry = intentFilter.getDataAuthority(0);
            if (authorityEntry != null && authorityEntry.getHost().equals("com.sec.android.app.sbrowser")) {
                return true;
            }
        }

        // The filter must not be restricted to any particular set of authorities
        if (resolveInfo.filter.authoritiesIterator() != null) {
            return false;
        }

        // The filter must support both HTTP and HTTPS.
        boolean supportsHttp = false;
        boolean supportsHttps = false;
        Iterator<String> schemeIter = resolveInfo.filter.schemesIterator();
        while (schemeIter.hasNext()) {
            String scheme = schemeIter.next();
            supportsHttp |= SCHEME_HTTP.equals(scheme);
            supportsHttps |= SCHEME_HTTPS.equals(scheme);

            if (supportsHttp && supportsHttps) {
                return true;
            }
        }

        // at least one of HTTP or HTTPS is not supported
        return false;
    }
}
