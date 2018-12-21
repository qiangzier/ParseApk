package com.hzq.dexparse.struct;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by hezhiqiang on 2018/12/20.
 */

public class TypeList {
    /**
     * struct type_list
     {
         uint size;
         ushort type_idx[size];
     }
     */

    public int size;//
    public List<Short> type_idx = new ArrayList<Short>();
}
