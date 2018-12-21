package com.hzq.dexparse;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;

import java.io.IOException;
import java.io.InputStream;

import okio.BufferedSource;
import okio.Okio;

/**
 * Created by hezhiqiang on 2018/12/18.
 */

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        DexParse.dexParseInit(getAssets());
        try {
            InputStream open = getAssets().open("Hello.dex");
            BufferedSource bufferedSource = Okio.buffer(Okio.source(open));
            byte[] bytes = bufferedSource.readByteArray();
            ParseDexUtil.main(bytes);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
