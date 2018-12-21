package com.hzq.dexparse.struct;

import com.hzq.dexparse.utils.Utils;

/**
 * Created by hezhiqiang on 2018/12/20.
 */

public class StringIdsItem {
    /**
     * struct string_ids_item
     {
     uint string_data_off;
     }
     */

    public int string_data_off;

    public static int getSize(){
        return 4;
    }

    @Override
    public String toString(){
        return Utils.bytesToHexString(Utils.int2ByteLe(string_data_off));
    }
}
