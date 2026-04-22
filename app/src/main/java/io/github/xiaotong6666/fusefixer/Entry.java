package io.github.xiaotong6666.fusefixer;

import android.app.AndroidAppHelper;
import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.core.content.ContextCompat;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import fusefixer.MainThreadTask;
import fusefixer.StatusBroadcastReceiver;

public class Entry implements IXposedHookLoadPackage {
    private static final String APP_PACKAGE = "io.github.xiaotong6666.fusefixer";
    private static final String ACTION_GET_STATUS = APP_PACKAGE + ".GET_STATUS";
    private static final String PACKAGE_MEDIA = "com.android.providers.media.module";
    private static final String PACKAGE_MEDIA_GOOGLE = "com.google.android.providers.media.module";

    private static HideConfig currentNativeHideConfig() {
        return new HideConfig(
                HideConfigNativeBridge.getCurrentEnableHideAllRootEntries(),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHideAllRootEntriesExemptions()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenRootEntryNames()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenRelativePaths()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenPackages()));
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        if (PACKAGE_MEDIA.equals(loadPackageParam.packageName)
                || PACKAGE_MEDIA_GOOGLE.equals(loadPackageParam.packageName)) {
            System.loadLibrary("fusefixer");
            Log.d("FuseFixer", "injected");
            new Handler(Looper.getMainLooper()).post(new MainThreadTask(0, this));
        }
    }

    public void registerStatusReceiver() {
        try {
            Application application = AndroidAppHelper.currentApplication();
            if (application == null) {
                Log.e("FuseFixer", "app is null??");
                return;
            }
            StatusBroadcastReceiver receiver = new StatusBroadcastReceiver(application, 0);
            IntentFilter filter = new IntentFilter(ACTION_GET_STATUS);
            if (Build.VERSION.SDK_INT >= 33) {
                application.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
            } else {
                ContextCompat.registerReceiver(application, receiver, filter, ContextCompat.RECEIVER_EXPORTED);
            }

            BroadcastReceiver configReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    final String requestedToken = intent.getStringExtra(HideConfigStore.EXTRA_RELOAD_TOKEN);
                    final android.os.Bundle bundle = HideConfigStore.loadViaProviderBundle(application);
                    final String providerToken = HideConfigStore.reloadTokenFromBundle(bundle);
                    final boolean tokenMatches = requestedToken != null && requestedToken.equals(providerToken);
                    boolean applied = false;
                    String message;
                    if (!tokenMatches) {
                        message = "reload token mismatch";
                    } else {
                        final HideConfig config = HideConfigStore.fromBundle(bundle);
                        if (config == null) {
                            message = "hide config unavailable";
                        } else {
                            try {
                                HideConfigNativeBridge.applyHideConfig(
                                        config.getEnableHideAllRootEntries(),
                                        config.getHideAllRootEntriesExemptions().toArray(new String[0]),
                                        config.getHiddenRootEntryNames().toArray(new String[0]),
                                        config.getHiddenRelativePaths().toArray(new String[0]),
                                        config.getHiddenPackages().toArray(new String[0]));
                                applied = true;
                                message = "hide config applied";
                            } catch (Throwable th) {
                                Log.e("FuseFixer", "applyHideConfig", th);
                                message = "apply failed: " + th.getClass().getSimpleName();
                            }
                        }
                    }
                    application.sendBroadcast(new Intent(HideConfigStore.ACTION_SET_CONFIG_STATUS)
                            .setPackage(APP_PACKAGE)
                            .putExtra(HideConfigStore.EXTRA_RELOAD_TOKEN, requestedToken)
                            .putExtra(HideConfigStore.EXTRA_RELOAD_APPLIED, applied)
                            .putExtra(HideConfigStore.EXTRA_RELOAD_MESSAGE, message));
                    Log.d("FuseFixer", "config reload broadcast applied=" + applied + " tokenMatches=" + tokenMatches);
                }
            };
            IntentFilter configFilter = new IntentFilter(HideConfigStore.ACTION_RELOAD_HIDE_CONFIG);
            if (Build.VERSION.SDK_INT >= 33) {
                application.registerReceiver(configReceiver, configFilter, Context.RECEIVER_EXPORTED);
            } else {
                ContextCompat.registerReceiver(
                        application, configReceiver, configFilter, ContextCompat.RECEIVER_EXPORTED);
            }

            BroadcastReceiver queryReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    final String queryToken = intent.getStringExtra(HideConfigStore.EXTRA_QUERY_TOKEN);
                    final HideConfig config = currentNativeHideConfig();
                    Intent reply = new Intent(HideConfigStore.ACTION_SET_APPLIED_HIDE_CONFIG)
                            .setPackage(APP_PACKAGE)
                            .putExtra(HideConfigStore.EXTRA_QUERY_TOKEN, queryToken)
                            .putExtras(HideConfigStore.toBundle(config));
                    application.sendBroadcast(reply);
                    Log.d("FuseFixer", "reported applied hide config queryToken=" + queryToken);
                }
            };
            IntentFilter queryFilter = new IntentFilter(HideConfigStore.ACTION_GET_APPLIED_HIDE_CONFIG);
            if (Build.VERSION.SDK_INT >= 33) {
                application.registerReceiver(queryReceiver, queryFilter, Context.RECEIVER_EXPORTED);
            } else {
                ContextCompat.registerReceiver(
                        application, queryReceiver, queryFilter, ContextCompat.RECEIVER_EXPORTED);
            }

            final boolean applied = HideConfigStore.reloadInjectedProcessConfig(application);
            Log.d("FuseFixer", "registered initialConfigApplied=" + applied);
            Log.d("FuseFixer", "registered");
        } catch (Throwable th) {
            Log.e("FuseFixer", "register", th);
        }
    }
}
