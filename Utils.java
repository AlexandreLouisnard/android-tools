package com.louisnard.utils;

import static android.graphics.Color.BLACK;
import static android.graphics.Color.WHITE;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.Point;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.Looper;
import android.provider.Settings;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.text.InputFilter;
import android.text.Spanned;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.Display;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodManager;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.core.app.ActivityCompat;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.portalp.technician.ui.activities_fragments.BaseActivity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.channels.FileChannel;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.DayOfWeek;
import java.time.format.TextStyle;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import javax.annotation.Nullable;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Helper class providing some tools to facilitate Android development.
 *
 * @author Alexandre Louisnard 2017
 */

public class Utils {

    public static final String TAG = Utils.class.getSimpleName();

    //region Objects & introspection

    /**
     * Tries to get {@code field} on the given {@link Object}.<br/>
     *
     * @param o     the {@link Object} on which to run the getter
     * @param field the Field to read from the Object
     * @return {runGetter(o, fieldName)}
     */
    public static Object runGetter(Object o, Field field) {
        return runGetter(o, field.getName());
    }

    /**
     * Tries to get {@code fieldName} on the given {@link Object}.<br/>
     * For instance, runGetter(obj, "door") will try to run obj.getDoor() and return the result or null if it failed.<br/>
     * <b>Note:</b> when using ProGuard, all objects on which this method is called must NOT be obfuscated
     *
     * @param o         the {@link Object} on which to run the getter
     * @param fieldName the name of the field to get, such as get"fieldName" is a method of the given object. The field name is case insensitive.
     * @return the result of the method invoked from the Object
     */
    public static Object runGetter(Object o, String fieldName) {
        for (Method method : o.getClass().getMethods()) {
            if ((method.getName().startsWith("get")) && (method.getName().length() == (fieldName.length() + 3))) {
                if (method.getName().toLowerCase(Locale.getDefault()).endsWith(fieldName.toLowerCase())) {
                    try {
                        return method.invoke(o);
                    } catch (IllegalAccessException | InvocationTargetException | NullPointerException | IllegalArgumentException e) {
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
     * @param type given {@link Class}
     * @return the list of the class fields {@link List <Field>}
     */
    public static List<Field> getAllFields(Class<?> type) {
        return _getAllFields(new LinkedList<>(), type);
    }

    /**
     * Recursive part of {@link #getAllFields(Class)}.
     *
     * @param fields empty list
     * @param type   given {@link Class}
     * @return {@link List<Field>} of the {@link Class} and SuperClass
     */
    private static List<Field> _getAllFields(List<Field> fields, Class<?> type) {
        fields.addAll(Arrays.asList(type.getDeclaredFields()));

        if (type.getSuperclass() != null) {
            _getAllFields(fields, type.getSuperclass());
        }

        return fields;
    }

    public static Object getFieldValue(Object o, String fieldName) {
        try {
            final Field field = o.getClass().getField(fieldName);
            //final Class fieldClass = field.getType();
            return field.get(o);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            return null;
        }

    }

    /**
     * Returns a cloned {@link Object} if the parameter is {@link Cloneable}, or directly the value if not.
     *
     * @param o {@link Object} to clone
     * @return Returns a cloned {@link Object}
     */
    public static <E> E cloneIfPossible(E o) {
        if (o == null) {
            return null;
        }
        if (o instanceof Cloneable && !o.getClass().isArray()) {
            try {
                return (E) o.getClass().getMethod("clone").invoke(o);
            } catch (Exception e) {
                e.printStackTrace();
                return o;
            }
        } else {
            return o;
        }
    }
    //endregion

    //region Binary & hexa tools
    public static byte[] decodeHex(final char[] data) {
        final int len = data.length;
        // Handle empty string - omitted for clarity's sake
        final byte[] out = new byte[len >> 1];
        // two characters form the hex value.
        for (int i = 0, j = 0; j < len; i++) {
            int f = Character.digit(data[j], 16) << 4;
            j++;
            f = f | Character.digit(data[j], 16);
            j++;
            out[i] = (byte) (f & 0xFF);
        }
        return out;
    }

    /**
     * Converts byte to hexadecimal {@link String}.
     *
     * @param b byte to convert
     * @return the binary {@link String} representation
     */
    public static String toBinaryString(byte b) {
        return String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
    }

    /**
     * Converts int to hexadecimal {@link String}.
     *
     * @param i int to convert
     * @return the binary {@link String} representation
     */
    public static String toBinaryString(int i) {
        return String.format("%16s", Integer.toBinaryString(i)).replace(' ', '0');
    }

    /**
     * Converts byte[] to hexadecimal {@link String}.
     *
     * @param bytes     byte array to convert
     * @param separator the separator between each byte.<br />
     *                  Pass <b>null</b> to ignore this parameter.
     * @param maxLength the max length of the {@link String}. If exceeded, the resulting {@link String} will be truncated.<br />
     *                  Pass <b></b>0 or negative value</b> to ignore this parameter.
     * @param reverse   <b>true</b> to reverse the order of bytes.
     * @return {@link String} hexadecimal of converted byte array
     */
    public static String toHexaString(Byte[] bytes, String separator, int maxLength, boolean reverse) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            if (reverse) {
                sb.insert(0, String.format("%1$02X%2$s", b, separator));

            } else {
                sb.append(String.format("%1$02X%2$s", b, separator));
            }
            if (maxLength > 0 && sb.length() >= maxLength) {
                break;
            }
        }
        return sb.toString();
    }

    public static String toHexaString(Byte[] bytes, String separator) {
        return toHexaString(bytes, separator, -1, false);
    }

    public static String toHexaString(Byte[] bytes, boolean reverse) {
        return toHexaString(bytes, "", -1, reverse);
    }

    public static String toHexaString(Byte[] bytes) {
        return toHexaString(bytes, "", -1, false);
    }

    public static String toHexaString(byte[] bytes) {
        return toHexaString(bytesToBytes(bytes), "", -1, false);
    }

    public static Byte[] bytesToBytes(byte[] bytes) {
        Byte[] byteObjects = new Byte[bytes.length];
        int i = 0;
        // Associating Byte array values with bytes. (byte[] to Byte[])
        for (byte b : bytes) {
            byteObjects[i++] = b;  // Autoboxing.
        }
        return byteObjects;
    }

    public static byte[] Bytestobytes(Byte[] byteObjects) {
        byte[] bytes = new byte[byteObjects.length];
        int i = 0;
        // Unboxing Byte values. (Byte[] to byte[])
        for (Byte b : byteObjects) {
            bytes[i++] = b.byteValue();
        }
        return bytes;
    }

    public static @Nullable
    Bitmap encodeAsQRCode(String str, int size) {
        BitMatrix result;
        try {
            result = new MultiFormatWriter().encode(str,
                    BarcodeFormat.QR_CODE, size, size, null);
        } catch (IllegalArgumentException | WriterException e) {
            return null;
        }
        int w = result.getWidth();
        int h = result.getHeight();
        int[] pixels = new int[w * h];
        for (int y = 0; y < h; y++) {
            int offset = y * w;
            for (int x = 0; x < w; x++) {
                pixels[offset + x] = result.get(x, y) ? BLACK : WHITE;
            }
        }
        Bitmap bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
        bitmap.setPixels(pixels, 0, size, 0, 0, w, h);
        return bitmap;
    }

    /**
     * Returns the digit of the given number at the given position (starting from 0).
     *
     * @param number   int
     * @param position position of the digit to return
     * @return digit at position
     * @throws IndexOutOfBoundsException exception if position invalid
     */
    public static byte getDigit(int number, int position) throws IndexOutOfBoundsException {
        return Byte.parseByte(Integer.toString(number).substring(position, position + 1));
    }

    /**
     * For the given {@code number}, returns the bit value at {@code bitIndex}.
     *
     * @param number   int
     * @param bitIndex index of the byte to return
     * @return the bit value (0 or 1).
     */
    public static int getBit(int number, int bitIndex) {
        return (number >> bitIndex) & 1;
    }

    /**
     * For the given {@code number}, sets the bit at {@code bitIndex} to {@code bitValue}, and returns the new number value.
     *
     * @param number   int
     * @param bitIndex 0 (LSB) to n (MSB)
     * @param bitValue 0 or 1
     * @return the new number value
     */
    public static int setBit(int number, int bitIndex, int bitValue) {
        switch (bitValue) {
            case 0:
                return number & ~(1 << bitIndex);
            case 1:
                return number | 1 << bitIndex;
            default:
                return number;
        }
    }

    /**
     * For the given {@code number}, toggles the bit value at {@code bitIndex}, and returns the new number value.
     *
     * @param number   int
     * @param bitIndex index of the byte to change
     * @return the new number value
     */
    public static int toggleBit(int number, int bitIndex) {
        return number ^ 1 << bitIndex;
    }
    //endregion

    //region Files & storage
    public static final String FILE_NAME_FORBIDDEN_CHARS = "?:\"*|/\\<>";

    public static InputFilter filterFILE_NAME_FORBIDDEN_CHARS = new InputFilter() {
        public CharSequence filter(CharSequence source, int start, int end, Spanned dest, int dstart, int dend) {
            if (source.length() < 1) {
                return null;
            }
            char last = source.charAt(source.length() - 1);
            if (FILE_NAME_FORBIDDEN_CHARS.indexOf(last) > -1) {
                return source.subSequence(0, source.length() - 1);
            }
            return null;
        }
    };

    // Checks if a volume containing external storage is available
    // for read and write.
    private static boolean isExternalStorageWritable() {
        return Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED);
    }

    // Checks if a volume containing external storage is available to at least read.
    private static boolean isExternalStorageReadable() {
        return Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED) ||
                Environment.getExternalStorageState().equals(Environment.MEDIA_MOUNTED_READ_ONLY);
    }

    public static String computeFileNameWithExt(String fileName, @Nullable String extension) {
        String fileNameWithExt = fileName;
        String computedExtension;
        if (extension != null && !extension.isEmpty()) {
            if (!extension.startsWith(".")) {
                computedExtension = "." + extension;
            } else {
                computedExtension = extension;
            }
            if (!fileName.toLowerCase(Locale.ROOT).endsWith(computedExtension.toLowerCase())) {
                fileNameWithExt += computedExtension;
            }
        }
        return fileNameWithExt;
    }

    public static File getFile(Context context, boolean isExternal, String dirName, String fileName, @Nullable String extension, boolean createParentDirsIfNeeded) {
        final String fileNameWithExt = computeFileNameWithExt(fileName, extension);
        final File rootAppDir = isExternal ? context.getExternalFilesDir(null) : context.getFilesDir();
        final File dir = new File(rootAppDir, dirName);
        if (!dir.exists() && createParentDirsIfNeeded) {
            dir.mkdirs();
        }
        final File file = new File(dir, fileNameWithExt);
        return file;
    }

    /**
     * Writes a file into the app-specific directory.
     *
     * @param context
     * @param isExternal <b>true</b> if other apps with Manifest.permission.READ_EXTERNAL_STORAGE or Manifest.permission.WRITE_EXTERNAL_STORAGE may read/write it.<br />
     *                   <b>false</b> if the file must be 100% private to this app
     * @param dirName
     * @param fileName   with or without the extension
     * @param extension  with or without the dot, example "admp" or ".admp"
     * @param append
     * @param data
     * @return
     */
    private static File writeFile(Context context, boolean isExternal, String dirName, String fileName, @Nullable String extension, boolean append, String data) throws IOException {
        final File file = getFile(context, isExternal, dirName, fileName, extension, true);
        final FileWriter fileWriter = new FileWriter(file, append);
        fileWriter.write(data);
        fileWriter.close();
        return file;
    }

    public static File writeExternalFile(Context context, String dirName, String fileName, @Nullable String extension, boolean append, String data) throws IOException {
        return writeFile(context, true, dirName, fileName, extension, append, data);
    }

    public static File writeInternalFile(Context context, String dirName, String fileName, @Nullable String extension, boolean append, String data) throws IOException {
        return writeFile(context, false, dirName, fileName, extension, append, data);
    }

    public static String readFile(Context context, boolean isExternal, String dirName, String fileName, @Nullable String extension) throws IOException {
        final File file = getFile(context, isExternal, dirName, fileName, extension, false);
        return readFile(file);
    }

    public static String readFile(File file) throws IOException {
        final StringBuilder text = new StringBuilder();
        final BufferedReader reader = new BufferedReader(new FileReader(file));
        String line;
        while ((line = reader.readLine()) != null) {
            text.append(line + '\n');
        }
        reader.close();
        return text.toString();
    }

    public static String readFile(Context context, Uri uri) throws IOException {
        final StringBuilder stringBuilder = new StringBuilder();
        try (InputStream inputStream = context.getContentResolver().openInputStream(uri);
             final BufferedReader reader = new BufferedReader(new InputStreamReader(Objects.requireNonNull(inputStream)))) {
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line);
            }
        }
        return stringBuilder.toString();
    }

    public static File[] getFilesList(Context context, boolean isExternal, String directory, boolean createParentDirsIfNeeded) {
//        File dir0 = Environment.getExternalStorageDirectory();
//        File dir1 = Environment.getDataDirectory();
//        File dir2 = Environment.getRootDirectory();
//        File dir3 = Environment.getStorageDirectory();
//        File dir4 = context.getExternalFilesDir(null);
//        File dir5 = context.getFilesDir();
        final File rootAppDir = isExternal ? context.getExternalFilesDir(null) : context.getFilesDir();
        final File dir = new File(rootAppDir, directory);
        if (!dir.exists() && createParentDirsIfNeeded) {
            dir.mkdirs();
        }
        File[] files = dir.listFiles();
        if (files == null) {
            files = new File[]{};
        }
        Arrays.sort(files);
        Log.d(TAG, "getFilesList(): " + files.length + " files");
        return files;
    }
    //endregion

    // region Code testing
    private static AtomicBoolean isRunningTest;

    /**
     * Indicates whether the current RUN is an Espresso test.
     *
     * @return <b>true</b> if it is an Espresso test
     */
    public static synchronized boolean isRunningEspressoTest() {
        if (isRunningTest == null) {
            boolean isTest;

            try {
                Class.forName("android.support.test.espresso.Espresso");
                isTest = true;
            } catch (ClassNotFoundException e) {
                isTest = false;
            }

            isRunningTest = new AtomicBoolean(isTest);
        }

        return isRunningTest.get();
    }
    //endregion

    //region Date & time
    public enum MyDayOfTheWeek {
        MONDAY(0x1),
        TUESDAY(0x2),
        WEDNESDAY(0x4),
        THURSDAY(0x8),
        FRIDAY(0x10),
        SATURDAY(0x20),
        SUNDAY(0x40);

        private final byte code;

        MyDayOfTheWeek(int code) {
            this.code = (byte) code;
        }

        public byte getCode() {
            return code;
        }

        @RequiresApi(api = Build.VERSION_CODES.O)
        public static String getSymbol(int position, boolean value) {
            return value ? (" " + DayOfWeek.of(position + 1).getDisplayName(TextStyle.NARROW, Locale.getDefault()) + " ") : " - ";

        }

    }

    public static Calendar timestampToCalendar(long timestamp) {
        Date d = new Date(timestamp);
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(d);
        return calendar;
    }
    //endregion

    //region Strings
    public static boolean checkIpv4AddressValidity(String ip) {
        if (ip == null) {
            return false;
        }

        final String ipv4Pattern = "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])";
        return ip.matches(ipv4Pattern);
    }

    public static boolean checkIpv6AddressValidity(String ip) {
        if (ip == null) {
            return false;
        }

        final String ipv6Pattern = "([0-9a-f]{1,4}:){7}([0-9a-f]){1,4}";
        return ip.matches(ipv6Pattern);
    }

    public static boolean checkEmailValidity(String email) {
        if (email == null) {
            return false;
        }

        final String emailPattern = "^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})$";
        return email.matches(emailPattern);

    }
    // endregion

    //region Android helpers
    @SuppressLint("HardwareIds")
    public static String getSmartphoneIdentifier(Context context) {
        return Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
    }

    public static void longLogD(String tag, String log) {
        int maxLogSize = 1000;
        for (int i = 0; i <= log.length() / maxLogSize; i++) {
            int start = i * maxLogSize;
            int end = (i + 1) * maxLogSize;
            end = end > log.length() ? log.length() : end;
            Log.d(tag, log.substring(start, end));
        }
    }

    /**
     * Ignore SSL errors when using Web Services. Dangerous, only use for debug.
     */
    public static void trustAllSSLCerts() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
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
                    }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((arg0, arg1) -> true);
        } catch (Exception e) {
        }
    }
    //endregion

    // region Android UI
    public static boolean hasPermissions(Context context, String[] permissions) {
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && context != null && permissions != null) {
            for (String permission : permissions) {
                if (ActivityCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Hides the Android soft keyboard.
     *
     * @param activity the current {@link Activity}
     */
    public static void hideKeyboard(Activity activity) {
        InputMethodManager imm = (InputMethodManager) activity.getSystemService(Activity.INPUT_METHOD_SERVICE);
        // Find the currently focused view, so we can grab the correct window token from it.
        View view = activity.getCurrentFocus();
        // If no view currently has focus, create a new one, just so we can grab a window token from it
        if (view == null) {
            view = new View(activity);
        }
        if (imm != null) {
            imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
        }
    }

    /**
     * Converts dp to px dimensions.
     *
     * @param dp int DensityPixel
     * @return int Pixel
     */
    public static int dpToPx(int dp) {
        return (int) (dp * Resources.getSystem().getDisplayMetrics().density);
    }

    /**
     * Converts px to dp dimensions.
     *
     * @param px int Pixel
     * @return int DensityPixel
     */
    public static int pxToDp(int px) {
        return (int) (px / Resources.getSystem().getDisplayMetrics().density);
    }

    public static boolean isUiThread() {
        return Looper.getMainLooper().getThread() == Thread.currentThread();
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

    @NonNull
    public static Point getDisplayDimensions(Context context) {
        WindowManager wm = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
        Display display = wm.getDefaultDisplay();

        DisplayMetrics metrics = new DisplayMetrics();
        display.getMetrics(metrics);
        int screenWidth = metrics.widthPixels;
        int screenHeight = metrics.heightPixels;

        // find out if status bar has already been subtracted from screenHeight
        display.getRealMetrics(metrics);
        int physicalHeight = metrics.heightPixels;
        int statusBarHeight = getStatusBarHeight(context);
        int navigationBarHeight = getNavigationBarHeight(context);
        int heightDelta = physicalHeight - screenHeight;
        if (heightDelta == 0 || heightDelta == navigationBarHeight) {
            screenHeight -= statusBarHeight;
        }

        return new Point(screenWidth, screenHeight);
    }

    public static int getStatusBarHeight(Context context) {
        Resources resources = context.getResources();
        int resourceId = resources.getIdentifier("status_bar_height", "dimen", "android");
        return (resourceId > 0) ? resources.getDimensionPixelSize(resourceId) : 0;
    }

    public static int getNavigationBarHeight(Context context) {
        Resources resources = context.getResources();
        int resourceId = resources.getIdentifier("navigation_bar_height", "dimen", "android");
        return (resourceId > 0) ? resources.getDimensionPixelSize(resourceId) : 0;
    }

    public static void releaseFocus(View view) {
        ViewParent parent = view.getParent();
        ViewGroup group = null;
        View child = null;
        while (parent != null) {
            if (parent instanceof ViewGroup) {
                group = (ViewGroup) parent;
                for (int i = 0; i < group.getChildCount(); i++) {
                    child = group.getChildAt(i);
                    if (child != view && child.isFocusable())
                        child.requestFocus();
                }
            }
            parent = parent.getParent();
        }
    }
    //endregion

}
