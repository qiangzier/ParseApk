package com.hzq.dexparse.struct;

import com.hzq.dexparse.utils.Utils;

/**
 * Created by hezhiqiang on 2018/12/20.
 */

public class TypeIdsItem {
    /**
     * struct type_ids_item
     {
     uint descriptor_idx;
     }
     */

    public static TypeIdsItem build(byte[] bytes) {
        TypeIdsItem item = new TypeIdsItem();
        item.descriptor_idx = Utils.byte2int(bytes);
        item.bytes = bytes;
        return item;
    }

    //descriptor_idx就是解析之后的字符串中的索引值
    public int descriptor_idx;

    //附加字段
    public byte[] bytes;

    public static int getSize(){
        return 4;
    }

    @Override
    public String toString(){
        return "type id---->hex:"+Utils.bytesToHexString(Utils.int2ByteLe(descriptor_idx)) + ",string_idx="+descriptor_idx;
    }
}
