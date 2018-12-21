package com.hzq.parseapk;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import com.hzq.dexparse.ParseDexUtil;

import java.io.IOException;
import java.io.InputStream;

import okio.BufferedSource;
import okio.Okio;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

//        DexParse.dexParseInit(getAssets());
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
