package com.hzq.dexparse.struct;

import com.hzq.dexparse.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by hezhiqiang on 2018/12/20.
 */

public class StringDataItem {
    /**
     * struct string_data_item
     {
         uleb128 utf16_size;
         ubyte data;
     }
     */

    /**
     *  上述描述里提到了 LEB128 （ little endian base 128 ) 格式 ，是基于 1 个 Byte 的一种不定长度的
     编码方式 。若第一个 Byte 的最高位为 1 ，则表示还需要下一个 Byte 来描述 ，直至最后一个 Byte 的最高
     位为 0 。每个 Byte 的其余 Bit 用来表示数据
     */

    public List<Byte> utf16_size = new ArrayList<>();
    public byte data;

    //附加内容
    public int size;
    public byte[] srcBytes;
    public String value;


    @Override
    public String toString() {
        return "string_data_item------>size hex:"+ Utils.bytesToHexString(Utils.int2ByteLe(size))+"=(int)"+size + ",value hex:"+Utils.bytesToHexString(srcBytes) + "="+value;
    }
}
