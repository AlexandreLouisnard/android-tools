package com.louisnard.utils;

import android.databinding.InverseMethod;

/**
 * This helper class is meant to replace {@link android.databinding.ViewDataBinding#safeUnbox(Byte)}... methods which for some reason have protected access.
 * <p>
 * In the data-binding expressions in the XML layouts (@{} et @={}), when not wrapping objects explicitly with {@link #safeUnbox(Byte)}... methods, critical warnings get generated at build time.
 * <p>
 * The @InverseMethod's are useful when using two-ways data-binding in the layouts (@={}).
 */
public class SafeUnbox {

    @InverseMethod("safeBox")
    public static int safeUnbox(java.lang.Integer boxed) {
        return boxed == null ? 0 : boxed;
    }

    public static Integer safeBox(int value) {
        return value;
    }

    @InverseMethod("safeBox")
    public static long safeUnbox(java.lang.Long boxed) {
        return boxed == null ? 0L : boxed;
    }

    @InverseMethod("safeBox")
    public static short safeUnbox(java.lang.Short boxed) {
        return boxed == null ? 0 : (short) boxed;
    }

    @InverseMethod("safeBox")
    public static byte safeUnbox(java.lang.Byte boxed) {
        return boxed == null ? 0 : (byte) boxed;
    }

    @InverseMethod("safeBox")
    public static char safeUnbox(java.lang.Character boxed) {
        return boxed == null ? '\u0000' : boxed;
    }

    @InverseMethod("safeBox")
    public static double safeUnbox(java.lang.Double boxed) {
        return boxed == null ? 0.0 : boxed;
    }

    @InverseMethod("safeBox")
    public static float safeUnbox(java.lang.Float boxed) {
        return boxed == null ? 0f : boxed;
    }

    public static Float safeBox(float value) {
        return value;
    }

    @InverseMethod("safeBox")
    public static boolean safeUnbox(java.lang.Boolean boxed) {
        return boxed != null && boxed;
    }

    public static Boolean safeBox(boolean value) {
        return value ? Boolean.TRUE : Boolean.FALSE;
    }

}
