package com.hzq.dexparse.struct;

import com.hzq.dexparse.utils.Utils;

/**
 * Created by hezhiqiang on 2018/12/19.
 */

public class CodeItem {
    /**
     * struct code_item
     {
         ushort registers_size;     //本段代码使用到的寄存器数目。
         ushort ins_size;           //method传入参数的数目 。
         ushort outs_size;          //本段代码调用其它method 时需要的参数个数 。
         ushort tries_size;         //try_item 结构的个数 。
         uint debug_info_off;       //偏移地址 ，指向本段代码的 debug 信息存放位置 ，是一个 debug_info_item 结构。
         uint insns_size;           //指令列表的大小 ，以 16-bit 为单位 。 insns 是 instructions 的缩写 。
         ushort insns [ insns_size ];
         ushort paddding;           // optional 值为 0 ，用于对齐字节 。
         try_item tries [ tyies_size ]; // 用于处理 java 中的 exception , 常见的语法有 try catch 。
         encoded_catch_handler_list handlers; // 用于处理 java 中的 exception , 常见的语法有 try catch 。
     }
     */

    public short registers_size;
    public short ins_size;
    public short outs_size;
    public short tries_size;
    public int debug_info_off;
    public int insns_size;
    public short[] insns;

    @Override
    public String toString(){
        return "regsize: dex="+Utils.bytesToHexString(Utils.short2Byte(registers_size)) + ",value=" +registers_size+"," +
                "ins_size: dex="+Utils.bytesToHexString(Utils.short2Byte(ins_size)) + ",value="+ins_size +"," +
                "outs_size: dex="+Utils.bytesToHexString(Utils.short2Byte(outs_size)) + ",value="+outs_size+",tries_size:"+tries_size+",debug_info_off:"+debug_info_off+"," +
                "insns_size: dex="+Utils.bytesToHexString(Utils.short2Byte(ins_size)) + ",value="+insns_size + "\ninsns:"+getInsnsStr();
    }

    private String getInsnsStr(){
        StringBuilder sb = new StringBuilder();
        for(int i=0;i<insns.length;i++){
            sb.append(Utils.bytesToHexString(Utils.short2Byte(insns[i]))+",");
        }
        return sb.toString();
    }
}
