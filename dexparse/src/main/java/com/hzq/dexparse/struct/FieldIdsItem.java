package com.hzq.dexparse.struct;

import com.hzq.dexparse.utils.Utils;

/**
 * Created by hezhiqiang on 2018/12/20.
 */

public class FieldIdsItem {
    /**
     * struct filed_id_item
     {
         ushort class_idx;
         ushort type_idx;
         uint name_idx;
     }
     */

    public short class_idx; //字段所属类型，对应type_id的索引
    public short type_idx;  //字段值所属类型，对应type_id的索引
    public int name_idx;    //字段名称，对应string_id的索引

    //附加字段
    public String class_str;
    public String type_str;
    public String name_str;

    public static int getSize(){
        return 2 + 2 + 4;
    }

    @Override
    public String toString(){
        return "class_idx hex=:"+ Utils.bytesToHexString(Utils.short2Byte(class_idx)) + ",type_index=" + class_idx + ",value=" + class_str
                + " type_idx hex=:"+ Utils.bytesToHexString(Utils.short2Byte(type_idx)) + ",type_index=" + type_idx + ",value=" + type_str
                + " name_idx hex=:"+ Utils.bytesToHexString(Utils.int2ByteLe(name_idx)) + ",string_index=" + name_idx + ",value=" + name_str;
    }
}
