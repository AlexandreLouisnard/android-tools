package com.louisnard.utils;

import android.app.Activity;
import android.app.Dialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.app.DialogFragment;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v7.app.AlertDialog;
import android.util.Log;
import android.view.KeyEvent;

import com.louisnard.utils.R;

import static android.content.DialogInterface.BUTTON_NEGATIVE;
import static android.content.DialogInterface.BUTTON_NEUTRAL;
import static android.content.DialogInterface.BUTTON_POSITIVE;


/**
 * A custom {@link DialogFragment} to show alert, popups, etc..
 * <p>
 * Created by a.louisnard on 29/05/2018.
 */
public class AlertDialogFragment extends DialogFragment implements DialogInterface.OnClickListener {

    public static final String TAG = AlertDialogFragment.class.getSimpleName();


    //<editor-fold desc="(dec) Constants">
    private static final String ARG_TITLE_RES_ID = "ARG_TITLE_RES_ID";
    private static final String ARG_TITLE = "ARG_TITLE";
    private static final String ARG_MESSAGE_RES_ID = "ARG_MESSAGE_RES_ID";
    private static final String ARG_MESSAGE = "ARG_MESSAGE";
    private static final String ARG_POSITIVE_BUTTON_RES_ID = "ARG_POSITIVE_BUTTON_RES_ID";
    private static final String ARG_POSITIVE_BUTTON = "ARG_POSITIVE_BUTTON";
    private static final String ARG_NEGATIVE_BUTTON_RES_ID = "ARG_NEGATIVE_BUTTON_RES_ID";
    private static final String ARG_NEGATIVE_BUTTON = "ARG_NEGATIVE_BUTTON";
    //</editor-fold>

    private AlertDialogFragmentListener mListener;
    private int mRequestCode;

    public interface AlertDialogFragmentListener {
        /**
         * Callback method invoked when the user has clicked a button on the dialog, therefore closing it.
         * <p>
         * <b>Note: </b> if a target fragment has been specified through {@link #setTargetFragment(Fragment, int)}, then {@link Fragment#onActivityResult(int, int, Intent)} will be invoked instead.
         *
         * @param requestCode the request code specified through {@link #setListener(AlertDialogFragmentListener, int)}
         * @param resultCode  the result code, can be either {@link Activity#RESULT_OK} or {@link Activity#RESULT_CANCELED}
         * @param data        extra data
         */
        void onResult(int requestCode, int resultCode, Bundle data);
    }

    /**
     * Returns an {@link AlertDialogFragment}.
     * @param titleResId
     * @param messageResId
     * @param positiveButtonResId
     * @param negativeButtonResId
     * @return
     */
    public static AlertDialogFragment newInstance(int titleResId, int messageResId, int positiveButtonResId, int negativeButtonResId) {
        AlertDialogFragment alertDialogFragment = new AlertDialogFragment();

        // Set arguments
        Bundle args = new Bundle();
        if (titleResId != 0) {
            args.putInt(ARG_TITLE_RES_ID, titleResId);
        }
        if (messageResId != 0) {
            args.putInt(ARG_MESSAGE_RES_ID, messageResId);
        }
        if (positiveButtonResId != 0) {
            args.putInt(ARG_POSITIVE_BUTTON_RES_ID, positiveButtonResId);
        }
        if (negativeButtonResId != 0) {
            args.putInt(ARG_NEGATIVE_BUTTON_RES_ID, negativeButtonResId);
        }
        alertDialogFragment.setArguments(args);

        return alertDialogFragment;
    }

    /**
     * Returns an {@link AlertDialogFragment}.
     * @param title
     * @param message
     * @param positiveButtonResId
     * @param negativeButtonResId
     * @return
     */
    public static AlertDialogFragment newInstance(String title, String message, int positiveButtonResId, int negativeButtonResId) {
        AlertDialogFragment alertDialogFragment = new AlertDialogFragment();

        // Set arguments
        Bundle args = new Bundle();
        if (title != null) {
            args.putString(ARG_TITLE, title);
        }
        if (message != null) {
            args.putString(ARG_MESSAGE, message);
        }
        if (positiveButtonResId != 0) {
            args.putInt(ARG_POSITIVE_BUTTON_RES_ID, positiveButtonResId);
        }
        if (negativeButtonResId != 0) {
            args.putInt(ARG_NEGATIVE_BUTTON_RES_ID, negativeButtonResId);
        }
        alertDialogFragment.setArguments(args);

        return alertDialogFragment;
    }

    /**
     * Returns an {@link AlertDialogFragment} with an OK positive button.
     *
     * @param titleResId
     * @param messageResId
     * @return
     */
    public static AlertDialogFragment newInstance(int titleResId, int messageResId) {
        return newInstance(titleResId, messageResId, android.R.string.ok, 0);
    }

    /**
     * Returns an {@link AlertDialogFragment} with an OK positive button.
     *
     * @param title
     * @param message
     * @return
     */
    public static AlertDialogFragment newInstance(String title, String message) {
        return newInstance(title, message, android.R.string.ok, 0);
    }


    @NonNull
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
        final AlertDialog.Builder builder = new AlertDialog.Builder(getContext());

        setStyle(DialogFragment.STYLE_NORMAL, 0);

        if (getArguments().containsKey(ARG_TITLE_RES_ID)) {
            builder.setTitle(getArguments().getInt(ARG_TITLE_RES_ID));
        } else if (getArguments().containsKey(ARG_TITLE)) {
            builder.setTitle(getArguments().getString(ARG_TITLE));
        }

        if (getArguments().containsKey(ARG_MESSAGE_RES_ID)) {
            builder.setMessage(getArguments().getInt(ARG_MESSAGE_RES_ID));
        } else if (getArguments().containsKey(ARG_MESSAGE)) {
            builder.setMessage(getArguments().getString(ARG_MESSAGE));
        }

        if (getArguments().containsKey(ARG_POSITIVE_BUTTON_RES_ID)) {
            builder.setPositiveButton(getArguments().getInt(ARG_POSITIVE_BUTTON_RES_ID), this);
        } else if (getArguments().containsKey(ARG_POSITIVE_BUTTON)) {
            builder.setPositiveButton(getArguments().getString(ARG_POSITIVE_BUTTON), this);
        }

        if (getArguments().containsKey(ARG_NEGATIVE_BUTTON_RES_ID)) {
            builder.setNegativeButton(getArguments().getInt(ARG_NEGATIVE_BUTTON_RES_ID), this);
        } else if (getArguments().containsKey(ARG_NEGATIVE_BUTTON)) {
            builder.setNegativeButton(getArguments().getString(ARG_NEGATIVE_BUTTON), this);
        }

        AlertDialog dialog = builder.create();

        // Custom dialog buttons color (otherwise they are the same as the normal buttons, though not visible with this theme)
        dialog.setOnShowListener(arg0 -> {
            if (dialog.getButton(AlertDialog.BUTTON_POSITIVE) != null) {
                dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(getContext().getResources().getColor(R.color.colorAccent));
            }
            if (dialog.getButton(AlertDialog.BUTTON_NEGATIVE) != null) {
                dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(getContext().getResources().getColor(R.color.colorAccent));
            }
        });

        // Prevent back key
        dialog.setOnKeyListener((dial, keyCode, event) -> {
            if (keyCode == KeyEvent.KEYCODE_BACK && event.getAction() == KeyEvent.ACTION_UP) {
                if (getTargetFragment() != null) {
                    getTargetFragment().onActivityResult(getTargetRequestCode(), Activity.RESULT_CANCELED, null);
                } else if (mListener != null) {
                    mListener.onResult(mRequestCode, Activity.RESULT_CANCELED, null);
                }
                return true;
            }
            return false;
        });

        dialog.setCanceledOnTouchOutside(false);

        return dialog;
    }

    /**
     * Sets the {@link AlertDialogFragmentListener} for this {@link AlertDialogFragment}.
     * <p>
     * <b>Note: </b> instead of the onDoorPositionButtonClickListener, a target fragment can be specified through {@link #setTargetFragment(Fragment, int)}. Then {@link Fragment#onActivityResult(int, int, Intent)} will be invoked instead of {@link AlertDialogFragmentListener#onResult(int, int, Bundle)}.
     *
     * @param listener
     * @param requestCode
     */
    public void setListener(AlertDialogFragmentListener listener, int requestCode) {
        mListener = listener;
        mRequestCode = requestCode;
    }

    @Override
    public void onClick(DialogInterface dialog, int which) {
        switch (which) {
            case BUTTON_POSITIVE:
                if (getTargetFragment() != null) {
                    getTargetFragment().onActivityResult(getTargetRequestCode(), Activity.RESULT_OK, null);
                } else if (mListener != null) {
                    mListener.onResult(mRequestCode, Activity.RESULT_OK, null);
                }
                break;
            case BUTTON_NEGATIVE:
                if (getTargetFragment() != null) {
                    getTargetFragment().onActivityResult(getTargetRequestCode(), Activity.RESULT_CANCELED, null);
                } else if (mListener != null) {
                    mListener.onResult(mRequestCode, Activity.RESULT_CANCELED, null);
                }
                break;
            case BUTTON_NEUTRAL:
                if (getTargetFragment() != null) {
                    getTargetFragment().onActivityResult(getTargetRequestCode(), Activity.RESULT_CANCELED, null);
                } else if (mListener != null) {
                    mListener.onResult(mRequestCode, Activity.RESULT_CANCELED, null);
                }
                break;
        }
    }

    @Override
    public void show(FragmentManager manager, String tag) {
        // Do not show AlertDialogs during Espresso TEST execution as they get stuck until the user clicks OK
        if (Utils.isRunningEspressoTest()) {
            if (mListener != null) {
                mListener.onResult(mRequestCode, Activity.RESULT_OK, null);
            }
            return;
        }

        try {
            super.show(manager, tag);
        } catch (IllegalStateException e) {
            Log.w(TAG, "show(): error:");
            e.printStackTrace();
        }
    }
}
