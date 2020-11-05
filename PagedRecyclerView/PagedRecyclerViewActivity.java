package com.louisnard.utils;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.DefaultItemAnimator;
import android.support.v7.widget.DividerItemDecoration;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.PagerSnapHelper;
import android.support.v7.widget.RecyclerView;
import android.widget.TextView;

import com.louisnard.utils.R;

public class PagedRecyclerViewActivity extends AppCompatActivity {

    private List<Object> mObjects;
    private RecyclerView mRecyclerView;
    private ObjectsAdapter mObjectsAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Inflate layout
        setContentView(R.layout.activity_paged_recycler_view);

        // Set-up RecyclerView with pager
        mRecyclerView = findViewById(R.id.recycler_view);
        final RecyclerView.LayoutManager layoutManager = new LinearLayoutManager(this, LinearLayoutManager.HORIZONTAL, false);
        mRecyclerView.setLayoutManager(layoutManager);
        PagerSnapHelper snapHelper = new PagerSnapHelper();
        snapHelper.attachToRecyclerView(mRecyclerView);
        mRecyclerView.addItemDecoration(new LinePagerIndicatorDecoration(getResources().getColor(R.color.colorAccent), getResources().getColor(R.color.colorPrimary)));
        mObjectsAdapter = new ObjectsAdapter(this, mObjects);
        mRecyclerView.setAdapter(mObjectsAdapter);
    }

    @Override
    public boolean onSupportNavigateUp() {
        onBackPressed();
        return true;
    }

}
