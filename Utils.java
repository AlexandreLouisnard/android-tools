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

        /* #region Java Objects & introspection */
        /**
         * Tries to get {@code field} on the given {@link Object}.<br/>
         *
         * @param o
         * @param field
         * @return
         */
        public static Object runGetter(Object o, Field field) {
                return runGetter(o, field.getName());
        }

        /**
         * Tries to get {@code fieldName} on the given {@link Object}.<br/>
         * For instance, runGetter(car, "door") will try to run car.getDoor() and return
         * the result or null if it failed.
         *
         * @param o
         * @param fieldName
         * @return
         */
        public static Object runGetter(Object o, String fieldName) {
                for (Method method : o.getClass().getMethods()) {
                        if ((method.getName().startsWith("get"))
                                        && (method.getName().length() == (fieldName.length() + 3))) {
                                if (method.getName().toLowerCase().endsWith(fieldName.toLowerCase())) {
                                        try {
                                                return method.invoke(o);
                                        } catch (IllegalAccessException | InvocationTargetException e) {
                                                Log.d(TAG, "Could not determine method: " + method.getName());
                                        }
                                }
                        }
                }
                return null;
        }

        /**
         * Gets all {@link Field}s for a given {@link Class}.
         *
         * @param type
         * @return
         */
        public static List<Field> getAllFields(Class<?> type) {
                return _getAllFields(new LinkedList<>(), type);
        }

        /**
         * Recursive part of {@link #getAllFields(Class)}.
         *
         * @param fields
         * @param type
         * @return
         */
        private static List<Field> _getAllFields(List<Field> fields, Class<?> type) {
                fields.addAll(Arrays.asList(type.getDeclaredFields()));

                if (type.getSuperclass() != null) {
                        _getAllFields(fields, type.getSuperclass());
                }

                return fields;
        }

        /**
         * Returns a cloned {@link Object} if the parameter is {@link Cloneable}, or
         * directly the value if not.
         *
         * @param o
         * @return
         */
        public static Object cloneIfPossible(Object o) {
                if (o == null) {
                        return null;
                }
                if (o instanceof Cloneable) {
                        try {
                                return o.getClass().getMethod("clone").invoke(o);
                        } catch (Exception e) {
                                e.printStackTrace();
                                return o;
                        }
                } else {
                        return o;
                }
        }
        /* #endregion */

        /* #region Binary & hexa tools */
        /**
         * Converts byte to hexadecimal {@link String}.
         *
         * @param b
         * @return the binary {@link String} representation
         */
        public static String toBinaryString(byte b) {
                return String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
        }

        /**
         * Converts int to hexadecimal {@link String}.
         *
         * @param i
         * @return the binary {@link String} representation
         */
        public static String toBinaryString(int i) {
                return String.format("%16s", Integer.toBinaryString(i)).replace(' ', '0');
        }

        /**
         * Converts byte[] to hexadecimal {@link String}.
         *
         * @param bytes
         * @return the hexadecimal {@link String} representation
         */
        public static String toHexaString(byte[] bytes) {
                StringBuilder sb = new StringBuilder();
                for (byte b : bytes) {
                        sb.append(String.format("%02X ", b));
                }
                return sb.toString();
        }

        /**
         * Converts byte[] to hexadecimal {@link String}.
         *
         * @param bytes
         * @param maxLength
         * @return the hexadecimal {@link String} representation
         */
        public static String toHexaString(byte[] bytes, int maxLength) {
                StringBuilder sb = new StringBuilder();
                for (byte b : bytes) {
                        sb.append(String.format("%02X ", b));
                        if (sb.length() >= maxLength) {
                                break;
                        }
                }
                return sb.toString();
        }

        /**
         * Returns the digit of the given number at the given position (starting from
         * 0).
         *
         * @param number
         * @param position
         * @return
         * @throws IndexOutOfBoundsException
         */
        public static byte getDigit(int number, int position) throws IndexOutOfBoundsException {
                return Byte.parseByte(Integer.toString(number).substring(position, position + 1));
        }

        /**
         * For the given {@code number}, returns the bit value at {@code bitIndex}.
         *
         * @param number
         * @param bitIndex
         * @return the bit value (0 or 1).
         */
        public static int getBit(int number, int bitIndex) {
                return (number >> bitIndex) & 1;
        }

        /**
         * For the given {@code number}, sets the bit at {@code bitIndex} to
         * {@code bitValue}, and returns the new number value.
         *
         * @param number
         * @param bitIndex 0 (LSB) to n (MSB)
         * @param bitValue 0 or 1
         * @return the new number value
         */
        public static int setBit(int number, int bitIndex, int bitValue) {
                if (bitValue == 0) {
                        return number & ~(1 << bitIndex);
                } else if (bitValue == 1) {
                        return number | 1 << bitIndex;
                } else {
                        return number;
                }
        }

        /**
         * For the given {@code number}, toggles the bit value at {@code bitIndex}, and
         * returns the new number value.
         *
         * @param number
         * @param bitIndex
         * @return the new number value
         */
        public static int toggleBit(int number, int bitIndex) {
                return number ^ 1 << bitIndex;
        }
        /* #endregion */

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
        /* #endregion */

        /* #region Date & time */
        public enum MyDayOfTheWeek {
                MONDAY(0x1), TUESDAY(0x2), WEDNESDAY(0x4), THURSDAY(0x8), FRIDAY(0x10), SATURDAY(0x20), SUNDAY(0x40);

                private final byte code;

                MyDayOfTheWeek(int code) {
                        this.code = (byte) code;
                }

                public byte getCode() {
                        return code;
                }

                public static String getSymbol(int position, boolean value) {
                        return value ? (" " + DayOfWeek.of(position + 1).getDisplayName(TextStyle.NARROW,
                                        Locale.getDefault()) + " ") : " - ";

                }

        }

        public static Calendar timestampToCalendar(long timestamp) {
                Date d = new Date(timestamp);
                Calendar calendar = Calendar.getInstance();
                calendar.setTime(d);
                return calendar;
        }
        /* #endregion */
}
