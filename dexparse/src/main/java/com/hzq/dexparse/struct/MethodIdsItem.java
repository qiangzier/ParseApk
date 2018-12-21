package com.hzq.dexparse.struct;

import com.hzq.dexparse.utils.Utils;

/**
 * Created by hezhiqiang on 2018/12/20.
 */

public class MethodIdsItem {
    /**
     * struct filed_id_item
     {
         ushort class_idx;
         ushort proto_idx;
         uint name_idx;
     }
     */

    public short class_idx; //表示本 method 所属的 class 类型 , class_idx 的值是 type_ids 的一个 index , 并且必须指向一 个 class 类型 。
    public short proto_idx; //描述该 method 的原型 ,指向 proto_ids 的一个 index 。
    public int name_idx;    //表示本 method 的名称 ,它的值是 string_ids 的一个 index 。

    //附加字段
    public String class_str;
    public String proto_str;
    public String name_str;

    public static int getSize(){
        return 2 + 2 + 4;
    }

    @Override
    public String toString(){
        return "class_idx hex=:"+ Utils.bytesToHexString(Utils.short2Byte(class_idx)) + ",type_index=" + class_idx + ",value=" + class_str
                + " proto_idx hex=:"+ Utils.bytesToHexString(Utils.short2Byte(proto_idx)) + ",type_index=" + proto_idx + ",value=" + proto_str
                + " name_idx hex=:"+ Utils.bytesToHexString(Utils.int2ByteLe(name_idx)) + ",string_index=" + name_idx + ",value=" + name_str;
    }
}
