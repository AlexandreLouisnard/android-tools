package com.louisnard.utils;

import android.content.Context;
import android.support.annotation.Nullable;
import android.support.v7.widget.RecyclerView;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.louisnard.utils.R;

import java.util.Collections;
import java.util.List;


/**
 * Created by a.louisnard on 05/04/2018.
 */

public class ObjectsAdapter extends RecyclerView.Adapter<ObjectsAdapter.ObjectViewHolder> {

    private Context mContext;
    private List<Object> mObjects;

    public ObjectsAdapter(Context context, List<Object> objects) {
        mContext = context;
        mObjects = objects;
    }

    public void setObjects(List<Object> objects) {
        mObjects = objects;
        Collections.sort(mObjects, (f1, f2) -> f1.getLastOccurenceDate().compareTo(f2.getLastOccurenceDate()));
        notifyDataSetChanged();
    }

    @Override
    public ObjectViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View itemView = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_object, parent, false);
        return new ObjectViewHolder(itemView);
    }

    @Override
    public void onBindViewHolder(ObjectViewHolder holder, int position) {
        Object object = mObjects.get(position);
        holder.mTextView.setText(object.getTitle());
    }

    @Override
    public int getItemCount() {
        return mObjects.size();
    }

    class ObjectViewHolder extends RecyclerView.ViewHolder {

        LinearLayout mRootItemView;
        TextView mTextView;

        public ObjectViewHolder(View itemView) {
            super(itemView);
            mRootItemView = (LinearLayout) itemView;
            mTextView = itemView.findViewById(R.id.text_view);
        }
    }
}
