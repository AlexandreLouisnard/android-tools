package com.louisnard.utils.model.utils;

import android.content.Context;
import android.content.SharedPreferences;

public class SharedPrefsUtils {

    private static final String SHARED_PREFS_FILE_NAME = "shared_prefs_portalp_installer";

    /**
     * Gets boolean data.
     *
     * @param context the context
     * @param key     the key
     * @return the boolean data
     */
    public static boolean getBooleanData(Context context, String key) {

        return context.getSharedPreferences(SHARED_PREFS_FILE_NAME, Context.MODE_PRIVATE).getBoolean(key, false);
    }

    /**
     * Gets int data.
     *
     * @param context the context
     * @param key     the key
     * @return the int data
     */
    public static int getIntData(Context context, String key) {
        return context.getSharedPreferences(SHARED_PREFS_FILE_NAME, Context.MODE_PRIVATE).getInt(key, 0);
    }

    /**
     * Gets string data.
     *
     * @param context the context
     * @param key     the key
     * @return the string data
     */
    // Get Data
    public static String getStringData(Context context, String key) {
        return context.getSharedPreferences(SHARED_PREFS_FILE_NAME, Context.MODE_PRIVATE).getString(key, null);
    }

    /**
     * Saves data.
     *
     * @param context the context
     * @param key     the key
     * @param val     the val
     */
    // Save Data
    public static void saveData(Context context, String key, String val) {
        context.getSharedPreferences(SHARED_PREFS_FILE_NAME, Context.MODE_PRIVATE).edit().putString(key, val).apply();
    }

    /**
     * Saves data.
     *
     * @param context the context
     * @param key     the key
     * @param val     the val
     */
    public static void saveData(Context context, String key, int val) {
        context.getSharedPreferences(SHARED_PREFS_FILE_NAME, Context.MODE_PRIVATE).edit().putInt(key, val).apply();
    }

    /**
     * Saves data.
     *
     * @param context the context
     * @param key     the key
     * @param val     the val
     */
    public static void saveData(Context context, String key, boolean val) {
        context.getSharedPreferences(SHARED_PREFS_FILE_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(key, val)
                .apply();
    }


    public static SharedPreferences.Editor getSharedPrefEditor(Context context, String pref) {
        return context.getSharedPreferences(pref, Context.MODE_PRIVATE).edit();
    }

    public static void saveData(SharedPreferences.Editor editor) {
        editor.apply();
    }
}
