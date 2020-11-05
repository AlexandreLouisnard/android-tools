package com.louisnard.utils;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.channels.FileChannel;

/**
 * Helper class providing some tools to facilitate Android development.
 *
 * @author Alexandre Louisnard 2017
 */

public class Utils {

        // Tag
        public static final String TAG = Utils.class.getSimpleName();

        /* #region Files & storage */
        /**
         * Writes {@code data} into the given file.
         *
         * @param dirName
         * @param fileName
         * @param append
         * @param data
         * @return the written file path, or <b>null</b> if it failed
         */
        public static String writeFileToExternalStorage(String dirName, String fileName, boolean append, String data) {
                try {
                        File externalStorage = Environment.getExternalStorageDirectory();
                        File dir = new File(externalStorage.getAbsolutePath() + "/" + dirName);
                        dir.mkdirs();
                        File file = new File(dir, fileName);
                        FileWriter fileWriter = new FileWriter(file, append);
                        fileWriter.write(data);
                        fileWriter.close();
                        return file.getAbsolutePath();
                } catch (IOException e) {
                        Log.e(TAG, "writeFileToExternalStorage() failed: " + e.toString());
                        return null;
                }
        }

        /**
         * For every item in {@code list} writes its {@link Object#toString()} value
         * into the given file.
         *
         * @param dirName
         * @param fileName
         * @param append
         * @param list
         * @return the written file path, or <b>null</b> if it failed
         */
        public static String writeFileToExternalStorage(String dirName, String fileName, boolean append, List list) {
                try {
                        File externalStorage = Environment.getExternalStorageDirectory();
                        File dir = new File(externalStorage.getAbsolutePath() + "/" + dirName);
                        dir.mkdirs();
                        File file = new File(dir, fileName);
                        FileWriter fileWriter = new FileWriter(file, append);
                        for (Object o : list) {
                                fileWriter.write(o.toString() + "\n");
                        }
                        fileWriter.close();
                        return file.getAbsolutePath();
                } catch (IOException e) {
                        Log.e(TAG, "writeFileToExternalStorage() failed: " + e.toString());
                        return null;
                }
        }

        /**
         * Copies the current application database to the external storage. If not
         * granted already, the function will ask for WRITE_EXTERNAL_STORAGE permission
         * et will need to be called again once the permission granted.
         *
         * @param activity     the calling activity.
         * @param databaseName the name of the database to copy.
         * @return <b>true</b> if the copy has succeeded. <b>false</b> otherwise.
         */
        public static boolean exportDatabaseToExternalStorage(Activity activity, String databaseName) {
                // Check for external storage write permission
                if (ContextCompat.checkSelfPermission(activity,
                                Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                        ActivityCompat.requestPermissions(activity,
                                        new String[] { Manifest.permission.WRITE_EXTERNAL_STORAGE }, 0);
                } else {
                        // If external storage write permission has been granted
                        try {
                                File currentDb = activity.getDatabasePath(databaseName);
                                File externalStoragePath = Environment.getExternalStorageDirectory();
                                File backupDb = new File(externalStoragePath, "backup_" + databaseName);
                                if (currentDb.exists()) {
                                        FileChannel src = new FileInputStream(currentDb).getChannel();
                                        FileChannel dst = new FileOutputStream(backupDb).getChannel();
                                        dst.transferFrom(src, 0, src.size());
                                        src.close();
                                        dst.close();
                                        Log.d(TAG, "Database copied to: " + backupDb.toString());
                                        return true;
                                }
                        } catch (Exception e) {
                                e.printStackTrace();
                        }
                }
                return false;
        }

        /**
     * Writes {@code data} into the given file.
     *
     * @param context
     * @param dirName  {@link String } directory name
     * @param fileName {@link String } file name
     * @param append   boolean true if append mode else false
     * @param data     {@link String } the data to write
     * @return the written absolute file path, or <b>null</b> if it failed
     */
    @SuppressWarnings("ResultOfMethodCallIgnored")
    public static File writeFile(Context context, String dirName, String fileName, boolean append, String data) {
        try {
            File dir = new File(context.getFilesDir(), dirName);
            dir.mkdirs();
            File file = new File(dir, fileName);
            FileWriter fileWriter = new FileWriter(file, append);
            fileWriter.write(data);
            fileWriter.close();
            return file;
        } catch (IOException e) {
            Log.e(TAG, "writeFile() failed: " + e.toString());
            return null;
        }
    }

    public static String readFile(Context context, String dirName, String fileName) {
        File dir = new File(context.getFilesDir(), dirName);
        File file = new File(dir, fileName);
        return readFile(file);
    }

    public static String readFile(File file) {
        StringBuilder text = new StringBuilder();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                text.append(line + '\n');
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return text.toString();
    }

    public static File[] getFilesList(Context context, String directory) {
//        File dir0 = Environment.getExternalStorageDirectory();
//        File dir1 = Environment.getDataDirectory();
//        File dir2 = Environment.getRootDirectory();
//        File dir3 = Environment.getStorageDirectory();
//        File dir4 = context.getExternalFilesDir(null);
//        File dir5 = context.getFilesDir();
        File dir = new File(context.getFilesDir(), directory);
        dir.mkdirs();
        File[] files = dir.listFiles();
        Log.d(TAG, "getFilesList(): " + files.length + " files");
        return files;
    }
        /* #endregion */

        /* #region Code testing */
        private static AtomicBoolean mIsRunningTest;

        /**
         * Indicates whether the current RUN is an Espresso test.
         *
         * @return <b>true</b> if it is an Espresso test
         */
        public static synchronized boolean isRunningEspressoTest() {
                if (null == mIsRunningTest) {
                        boolean istest;

                        try {
                                Class.forName("android.support.test.espresso.Espresso");
                                istest = true;
                        } catch (ClassNotFoundException e) {
                                istest = false;
                        }

                        mIsRunningTest = new AtomicBoolean(istest);
                }

                return mIsRunningTest.get();
        }
        /* #endregion */

        /* #region Android stuff */
        /**
         * Indicates whether the user has granted the given permissions to the
         * application.
         *
         * @param context
         * @param permissions
         * @return
         */
        public static boolean hasPermissions(Context context, String[] permissions) {
                if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && context != null
                                && permissions != null) {
                        for (String permission : permissions) {
                                if (ActivityCompat.checkSelfPermission(context,
                                                permission) != PackageManager.PERMISSION_GRANTED) {
                                        return false;
                                }
                        }
                }
                return true;
        }

        public static String getSmartphoneIdentifier(Context context) {
                return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
        }

        /**
         * Ignore SSL errors when using Web Services. Dangerous, only use for debug.
         */
        public static void trustAllSSLCerts() {
                try {
                        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                                public X509Certificate[] getAcceptedIssuers() {
                                        X509Certificate[] myTrustedAnchors = new X509Certificate[0];
                                        return myTrustedAnchors;
                                }

                                @Override
                                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                                }

                                @Override
                                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                                }
                        } };

                        SSLContext sc = SSLContext.getInstance("SSL");
                        sc.init(null, trustAllCerts, new SecureRandom());
                        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
                        HttpsURLConnection.setDefaultHostnameVerifier((arg0, arg1) -> true);
                } catch (Exception e) {
                }
        }

        public static Activity getActivity(Context context) {
                while (context instanceof ContextWrapper) {
                    if (context instanceof Activity) {
                        return (Activity) context;
                    }
                    context = ((ContextWrapper) context).getBaseContext();
                }
                return null;
            }
        /* #endregion */

        /* #region UI */
        /**
         * Loads a new {@link Fragment} within this {@link AppCompatActivity}, if not
         * already loaded.<br/>
         * <p>
         * <b>Note:</b> to use the default implementation, the {@link AppCompatActivity}
         * layout must contain a {@link FrameLayout} with id = R.id.fragment_container.
         *
         * @param fragment    the {@link Fragment} to load.
         * @param forceReload <b>true</b> to force reload even if the fragment is
         *                    already the one displayed on screen.<br/>
         *                    <b>false</b> otherwise.
         */
        default void changeFragment(Fragment fragment, boolean forceReload) {

                if (!(this instanceof AppCompatActivity)
                                || ((AppCompatActivity) this).findViewById(R.id.fragment_container) == null) {
                        return;
                }

                ((AppCompatActivity) this).runOnUiThread(() -> {
                        if (fragment == null) {
                                Log.w(TAG, "changeFragment() called with null fragment parameter, returning");
                                return;
                        }
                        final String tag = fragment.getClass().getSimpleName();
                        if (!forceReload) {
                                final Fragment currentFragment = ((AppCompatActivity) this).getSupportFragmentManager()
                                                .findFragmentByTag(tag);
                                if (currentFragment != null && currentFragment.isVisible()) {
                                        // Already on the good fragment
                                        return;
                                }
                        }
                        Log.d(TAG, "changeFragment() to " + tag);
                        ((AppCompatActivity) this).getSupportFragmentManager().beginTransaction()
                                        .replace(R.id.fragment_container, fragment, tag).commit();
                });
        }

        /**
         * Overlays a new {@link Fragment} as a pop-up over the main fragment.<br/>
         * <p>
         * <b>Note:</b> to use the default implementation, the {@link AppCompatActivity}
         * layout must contain:<br/>
         * - a {@link FrameLayout} with id = R.id.fragment_overlay with an hardcoded
         * size and a non-transparent background (color or drawable).<br/>
         * - a {@link View} with id R.id.fade_background with a background (may have
         * some alpha), used to grey out the background fragment.<br/>
         *
         * @param fragment the {@link Fragment} to overlay or <b>null</b> to remove any
         *                 currently overlaid fragment.
         * @param tag      the tag of the fragment to overlay (or remove if
         *                 {@param fragment} is null) or <b>null</b> to remove any
         *                 currently overlaid fragment.
         */
        default void overlayFragment(@Nullable Fragment fragment, String tag) {

                if (!(this instanceof AppCompatActivity)
                                || ((AppCompatActivity) this).findViewById(R.id.fragment_overlay) == null
                                || ((AppCompatActivity) this).findViewById(R.id.fade_background) == null) {
                        return;
                }

                ((AppCompatActivity) this).runOnUiThread(() -> {
                        if (fragment == null) {
                                Fragment overlayFragment = null;
                                if (tag != null) {
                                        // Remove overlay fragment matching tag
                                        overlayFragment = ((AppCompatActivity) this).getSupportFragmentManager()
                                                        .findFragmentByTag(tag);
                                } else {
                                        // Remove any kind of overlay fragment
                                        overlayFragment = ((AppCompatActivity) this).getSupportFragmentManager()
                                                        .findFragmentById(R.id.fragment_overlay);
                                }
                                if (overlayFragment != null) {
                                        Log.d(TAG, "overlayFragment(): removing overlay");
                                        ((AppCompatActivity) this).getSupportFragmentManager().beginTransaction()
                                                        .remove(overlayFragment).commit();
                                        ((AppCompatActivity) this).findViewById(R.id.fragment_overlay)
                                                        .setVisibility(GONE);
                                        ((AppCompatActivity) this).findViewById(R.id.fade_background)
                                                        .setVisibility(GONE);
                                        // Re-enable UI interactions
                                        ((AppCompatActivity) this).getWindow()
                                                        .clearFlags(WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE);
                                }
                        } else {
                                // Show overlay fragment and disable UI interactions
                                ((AppCompatActivity) this).getWindow()
                                                .addFlags(WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE);
                                ((AppCompatActivity) this).findViewById(R.id.fragment_overlay).setVisibility(VISIBLE);
                                ((AppCompatActivity) this).findViewById(R.id.fade_background).setVisibility(VISIBLE);
                                final Fragment currentFragment = ((AppCompatActivity) this).getSupportFragmentManager()
                                                .findFragmentByTag(tag);
                                if (currentFragment == null || !currentFragment.isVisible()) {
                                        Log.d(TAG, "overlayFragment() " + tag);
                                        ((AppCompatActivity) this).getSupportFragmentManager().beginTransaction()
                                                        .replace(R.id.fragment_overlay, fragment, tag).commit();
                                }
                        }
                });
        }

        public static void hideKeyboard(Activity activity) {
                InputMethodManager imm = (InputMethodManager) activity.getSystemService(Activity.INPUT_METHOD_SERVICE);
                // Find the currently focused view, so we can grab the correct window token from
                // it.
                View view = activity.getCurrentFocus();
                // If no view currently has focus, create a new one, just so we can grab a
                // window token from it
                if (view == null) {
                        view = new View(activity);
                }
                imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
        }

        /**
         * Converts dp to px dimensions.
         *
         * @param dp
         * @return
         */
        public static int dpToPx(int dp) {
                return (int) (dp * Resources.getSystem().getDisplayMetrics().density);
        }

        /**
         * Converts px to dp dimensions.
         *
         * @param px
         * @return
         */
        public static int pxToDp(int px) {
                return (int) (px / Resources.getSystem().getDisplayMetrics().density);
        }

        /**
     * Calls {@link BaseActivity#toast(String)}.
     *
     * @param message string to display
     */
    public static void toast(Context context, int messageResId) {
        Activity activity = getActivity(context);
        if (activity != null && activity instanceof BaseActivity) {
            ((BaseActivity) activity).toast(messageResId);
        } else {
            Toast.makeText(context, messageResId, Toast.LENGTH_LONG).show();
        }
    }

    /**
     * Calls {@link BaseActivity#toast(String)}.
     *
     * @param message string to display
     */
    public static void toast(Context context, String message) {
        Activity activity = getActivity(context);
        if (activity != null && activity instanceof BaseActivity) {
            ((BaseActivity) activity).toast(message);
        } else {
            Toast.makeText(context, message, Toast.LENGTH_LONG).show();
        }
    }

        /**
     * Mutates and applies a filter that converts the given drawable to a Gray
     * image. This method may be used to simulate the color of disable icons in
     * Honeycomb's ActionBar.
     *
     * @return a mutated version of the given drawable with a color filter applied.
     */
    public static Drawable convertDrawableToGrayScale(Drawable drawable) {
        if (drawable == null)
            return null;

        Drawable res = drawable.mutate();
        res.setColorFilter(Color.GRAY, PorterDuff.Mode.SRC_IN);
        return res;
    }

        /* #endregion */

}
