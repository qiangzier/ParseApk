package com.hzq.dexparse.struct;

import com.hzq.dexparse.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by hezhiqiang on 2018/12/20.
 */

public class ProtoIdsItem {
    /**
     * struct proto_id_item
     {
         uint shorty_idx;
         uint return_type_idx;
         uint parameters_off;
     }
     */

    public int shorty_idx;      //跟 type_ids 一样 ,它的值是一个 string_ids 的 index 号
    public int return_type_idx; //它的值是一个 type_ids 的 index 号 ,表示该 method 原型的返回值类型
    public int parameters_off;  //parameters_off, 后缀 off 是 offset，指向 method 原型的参数列表 type_list ; 若 method 没有参数，值为 0

    //辅助字段
    public String shorty_str;
    public String return_type_str;

    //这个不是公共字段，而是为了存储方法原型中的参数类型名和参数个数
    public List<String> parametersListStr = new ArrayList<>();
    //存储索引
    public List<Short> parametersTypeIdx = new ArrayList<>();
    public int parameterCount;

    private String listToString() {
        String result = "";
        if(parameters_off > 0) {
            for (int i = 0; i < parametersListStr.size(); i++) {
                String str = parametersListStr.get(i);
                String hex = Utils.bytesToHexString(Utils.short2Byte(parametersTypeIdx.get(i)));
                result += "param hex="+hex + ",value="+str + "   ";
            }
        }
        return result;
    }

    public static int getSize(){
        return 4 + 4 + 4;
    }

    public String getMethodStr() {
        String result = "(";
        if(parameters_off > 0) {
            for (int i = 0; i < parametersListStr.size(); i++) {
                result += "p" + i + ":" + parametersListStr.get(i);
                if (i != parameterCount)
                    result += ",";
            }
        }
        result += ") : " + return_type_str;
        return result;
    }

    @Override
    public String toString(){
        return "shorty_idx: hex="+ Utils.bytesToHexString(Utils.int2ByteLe(shorty_idx))+",value="+shorty_str+";" +
                "return_type_idx: hex="+ Utils.bytesToHexString(Utils.int2ByteLe(return_type_idx))+",value="+return_type_str+";" +
                "parameters_off:hex="+ Utils.bytesToHexString(Utils.int2ByteLe(parameters_off))+",value="+listToString();
    }

}
