package io.github.xiaotong6666.fusefixer

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.util.Log

object HideConfigStore {
    const val APP_PACKAGE: String = "io.github.xiaotong6666.fusefixer"
    const val PACKAGE_MEDIA: String = "com.android.providers.media.module"
    const val PACKAGE_MEDIA_GOOGLE: String = "com.google.android.providers.media.module"
    const val ACTION_RELOAD_HIDE_CONFIG: String = "io.github.xiaotong6666.fusefixer.RELOAD_HIDE_CONFIG"
    const val ACTION_SET_CONFIG_STATUS: String = "io.github.xiaotong6666.fusefixer.SET_CONFIG_STATUS"
    const val ACTION_GET_APPLIED_HIDE_CONFIG: String = "io.github.xiaotong6666.fusefixer.GET_APPLIED_HIDE_CONFIG"
    const val ACTION_SET_APPLIED_HIDE_CONFIG: String = "io.github.xiaotong6666.fusefixer.SET_APPLIED_HIDE_CONFIG"
    const val EXTRA_RELOAD_TOKEN: String = "reload_token"
    const val EXTRA_RELOAD_APPLIED: String = "reload_applied"
    const val EXTRA_RELOAD_MESSAGE: String = "reload_message"
    const val EXTRA_QUERY_TOKEN: String = "query_token"
    private const val PREFS_NAME = "hide_config"
    private const val METHOD_GET_HIDE_CONFIG = "get_hide_config"
    private const val AUTHORITY = "io.github.xiaotong6666.fusefixer.hideconfig"
    private const val KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES = "enable_hide_all_root_entries"
    private const val KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS = "hide_all_root_entries_exemptions"
    private const val KEY_HIDDEN_ROOT_ENTRY_NAMES = "hidden_root_entry_names"
    private const val KEY_HIDDEN_RELATIVE_PATHS = "hidden_relative_paths"
    private const val KEY_HIDDEN_PACKAGES = "hidden_packages"
    private const val KEY_RELOAD_TOKEN = "reload_token"

    private val providerUri: Uri = Uri.parse("content://$AUTHORITY")

    fun load(context: Context): HideConfig {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val defaults = HideConfigDefaults.value
        return HideConfig(
            enableHideAllRootEntries = prefs.getBoolean(
                KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES,
                defaults.enableHideAllRootEntries,
            ),
            hideAllRootEntriesExemptions = parseStoredList(
                prefs.getString(
                    KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS,
                    encodeList(defaults.hideAllRootEntriesExemptions),
                ),
            ),
            hiddenRootEntryNames = parseStoredList(
                prefs.getString(
                    KEY_HIDDEN_ROOT_ENTRY_NAMES,
                    encodeList(defaults.hiddenRootEntryNames),
                ),
            ),
            hiddenRelativePaths = parseStoredList(
                prefs.getString(
                    KEY_HIDDEN_RELATIVE_PATHS,
                    encodeList(defaults.hiddenRelativePaths),
                ),
            ),
            hiddenPackages = parseStoredList(
                prefs.getString(
                    KEY_HIDDEN_PACKAGES,
                    encodeList(defaults.hiddenPackages),
                ),
            ),
        )
    }

    fun save(context: Context, config: HideConfig) {
        save(context, config, null)
    }

    fun save(context: Context, config: HideConfig, reloadToken: String?) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES, config.enableHideAllRootEntries)
            .putString(
                KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS,
                encodeList(config.hideAllRootEntriesExemptions),
            )
            .putString(KEY_HIDDEN_ROOT_ENTRY_NAMES, encodeList(config.hiddenRootEntryNames))
            .putString(KEY_HIDDEN_RELATIVE_PATHS, encodeList(config.hiddenRelativePaths))
            .putString(KEY_HIDDEN_PACKAGES, encodeList(config.hiddenPackages))
            .putString(KEY_RELOAD_TOKEN, reloadToken)
            .apply()
    }

    @JvmStatic
    fun toBundle(config: HideConfig): Bundle = Bundle().apply {
        putBoolean(KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES, config.enableHideAllRootEntries)
        putStringArray(
            KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS,
            config.hideAllRootEntriesExemptions.toTypedArray(),
        )
        putStringArray(KEY_HIDDEN_ROOT_ENTRY_NAMES, config.hiddenRootEntryNames.toTypedArray())
        putStringArray(KEY_HIDDEN_RELATIVE_PATHS, config.hiddenRelativePaths.toTypedArray())
        putStringArray(KEY_HIDDEN_PACKAGES, config.hiddenPackages.toTypedArray())
    }

    @JvmStatic
    fun fromBundle(bundle: Bundle?): HideConfig? {
        if (bundle == null) return null
        return HideConfig(
            enableHideAllRootEntries = bundle.getBoolean(KEY_ENABLE_HIDE_ALL_ROOT_ENTRIES, false),
            hideAllRootEntriesExemptions =
            bundle.getStringArray(KEY_HIDE_ALL_ROOT_ENTRIES_EXEMPTIONS)?.toList().orEmpty(),
            hiddenRootEntryNames = bundle.getStringArray(KEY_HIDDEN_ROOT_ENTRY_NAMES)?.toList().orEmpty(),
            hiddenRelativePaths = bundle.getStringArray(KEY_HIDDEN_RELATIVE_PATHS)?.toList().orEmpty(),
            hiddenPackages = bundle.getStringArray(KEY_HIDDEN_PACKAGES)?.toList().orEmpty(),
        )
    }

    @JvmStatic
    fun loadViaProviderBundle(context: Context): Bundle? = try {
        context.contentResolver.call(providerUri, METHOD_GET_HIDE_CONFIG, null, null)
    } catch (t: Throwable) {
        Log.e("FuseFixer", "loadViaProvider", t)
        null
    }

    @JvmStatic
    fun loadViaProvider(context: Context): HideConfig? = fromBundle(loadViaProviderBundle(context))

    @JvmStatic
    fun reloadTokenFromBundle(bundle: Bundle?): String? = bundle?.getString(KEY_RELOAD_TOKEN)

    @JvmStatic
    fun reloadInjectedProcessConfig(context: Context): Boolean {
        val config = loadViaProvider(context) ?: return false
        return try {
            HideConfigNativeBridge.applyHideConfig(
                config.enableHideAllRootEntries,
                config.hideAllRootEntriesExemptions.toTypedArray(),
                config.hiddenRootEntryNames.toTypedArray(),
                config.hiddenRelativePaths.toTypedArray(),
                config.hiddenPackages.toTypedArray(),
            )
            true
        } catch (t: Throwable) {
            Log.e("FuseFixer", "reloadInjectedProcessConfig", t)
            false
        }
    }

    fun sendReloadBroadcast(context: Context, reloadToken: String) {
        listOf(
            PACKAGE_MEDIA_GOOGLE,
            PACKAGE_MEDIA,
        ).forEach { packageName ->
            context.sendBroadcast(
                android.content.Intent(ACTION_RELOAD_HIDE_CONFIG)
                    .setPackage(packageName)
                    .putExtra(EXTRA_RELOAD_TOKEN, reloadToken),
            )
        }
    }

    fun sendAppliedConfigQueryBroadcast(context: Context, queryToken: String) {
        listOf(
            PACKAGE_MEDIA_GOOGLE,
            PACKAGE_MEDIA,
        ).forEach { packageName ->
            context.sendBroadcast(
                android.content.Intent(ACTION_GET_APPLIED_HIDE_CONFIG)
                    .setPackage(packageName)
                    .putExtra(EXTRA_QUERY_TOKEN, queryToken),
            )
        }
    }

    private fun encodeList(values: List<String>): String = values.joinToString("\n")

    private fun parseStoredList(value: String?): List<String> {
        if (value.isNullOrBlank()) return emptyList()
        return HideConfigDefaults.parseEditorText(value)
    }
}
