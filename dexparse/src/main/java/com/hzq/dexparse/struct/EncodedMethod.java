package com.hzq.dexparse.struct;

import com.hzq.dexparse.utils.Utils;

/**
 * Created by hezhiqiang on 2018/12/19.
 */

public class EncodedMethod {
    /**
     * struct encoded_method
     {
         uleb128 method_idx_diff;
         uleb128 access_flags;
         uleb128 code_off;
     }
     */

    public byte[] method_idx_diff;
    public byte[] access_flags;
    public byte[] code_off;

    //附加字段
    public CodeItem codeItem;

    @Override
    public String toString() {
        return "method_idx_diff:" + Utils.bytesToHexString(method_idx_diff) + "," + Utils.bytesToHexString(Utils.int2Byte(Utils.decodeUleb128(method_idx_diff)))
                + ",access_flags:" + Utils.bytesToHexString(access_flags) + "," + Utils.bytesToHexString(Utils.int2Byte(Utils.decodeUleb128(access_flags)))
                + ",code_off:" + Utils.bytesToHexString(code_off) + "," + Utils.bytesToHexString(Utils.int2Byte(Utils.decodeUleb128(code_off))) + ",codeItem="+codeItem.toString();

    }
}
