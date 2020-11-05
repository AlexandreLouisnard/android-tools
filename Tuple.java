package com.louisnard.utils;

public class Tuple<X, Y> {

    public static final String TAG = Tuple.class.getSimpleName();

    public final X x;
    public final Y y;

    public Tuple(X x, Y y) {
        this.x = x;
        this.y = y;
    }
}
