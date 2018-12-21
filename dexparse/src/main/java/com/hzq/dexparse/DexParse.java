package com.hzq.dexparse;

import android.content.res.AssetManager;
import android.util.Log;

import com.hzq.dexparse.utils.Utils;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UTFDataFormatException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import okio.Buffer;
import okio.BufferedSource;
import okio.ByteString;
import okio.Okio;

/**
 * Created by hezhiqiang on 2018/12/12.
 */

public class DexParse {

    private static String DEX_NAME = "Hello.dex";
    private static Map<String,ByteString> dexCache = new HashMap<>();
    private static Map<Integer,String> stringCache = new HashMap<>();
    private static Map<Integer,String> typeCache = new HashMap<>();
    private static Map<Integer,String> protoCache = new HashMap<>();
    private static Map<Integer,String> methodCache = new HashMap<>();
    private static Map<String,ArrayList<Integer>> dexStringIdsCache = new HashMap<>();

    public static void dexParseInit(AssetManager assetManager) {
        try {
            dexHeaderParse(assetManager.open(DEX_NAME));
            dexMapItems(assetManager.open(DEX_NAME));
            /**
             * 读取string_ids的偏移量
             */
            dexStringIds(assetManager.open(DEX_NAME));
            /**
             * 根据string_ids的偏移量读对应位置的值
             */
            stringCache = readStringIds(assetManager);

            /**
             * 读取types数据，dex中所有类型，如：类类型，基本数据类型等
             */
            typeCache = readTypesIds(assetManager);

            /**
             * 这个区域存放的是method的函数原型，参数，返回类型等等
             */
            protoCache = readProtosIds(assetManager);
            /**
             * 读取field
             */
            readFieldIds(assetManager);
            methodCache = readMethodIds(assetManager);
            readClassIds(assetManager);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 解析Dex Header部分
     * @param open
     */
    private static void dexHeaderParse(InputStream open) {
        BufferedSource bufferedSource = Okio.buffer(Okio.source(open));
        try {
            //读取magic，占用8个字节，读取开始地址的8个字节即可
            ByteString magicStr = readByteString(bufferedSource,8);
            //输出16进制
            log("magic hex: = " + magicStr.hex());
            //输出文本内容
//            log("magic string: = " + magicStr.utf8());

            //CheckSum 占4个字节，继magic之后读取4个字节
            ByteString checkSum = readByteString(bufferedSource,4);
            //输出16进制
            log("checkSum hex: = " + checkSum.hex());

            //读取Signature
            //signature有20个字节，读完checksum后取20个字节即可
            ByteString signature = readByteString(bufferedSource,20);
            //输出16进制
            log("signature hex: = " + signature.hex());

            //读取file_size
            ByteString dexSize = readByteString(bufferedSource,4);
            //输出16进制
            log("dexSize hex: = " + dexSize.hex());

            //读取header_size
            ByteString header_size = readByteString(bufferedSource,4);
            //输出16进制
            log("header_size hex: = " + header_size.hex());

            //endian_tag
            ByteString endian_tag = readByteString(bufferedSource,4);
            //输出16进制
            log("endian_tag hex: = " + endian_tag.hex());

            //link_size
            ByteString link_size = readByteString(bufferedSource,4);
            //输出16进制
            log("link_size hex: = " + link_size.hex());

            //link_off
            ByteString link_off = readByteString(bufferedSource,4);
            //输出16进制
            log("link_off hex: = " + link_off.hex());

            //map_off
            ByteString map_off = readByteString(bufferedSource,4);
            //输出16进制
            log("map_off hex: = " + map_off.hex());
            dexCache.put("map_off",map_off);

            //string_ids_size
            ByteString string_ids_size = readByteString(bufferedSource,4);
            //输出16进制
            log("string_ids_size hex: = " + string_ids_size.hex());
            dexCache.put("string_ids_size",string_ids_size);

            //string_ids_off
            ByteString string_ids_off = readByteString(bufferedSource,4);
            //输出16进制
            log("string_ids_off hex: = " + string_ids_off.hex());
            dexCache.put("string_ids_off",string_ids_off);

            //type_ids_size
            ByteString type_ids_size = readByteString(bufferedSource,4);
            //输出16进制
            log("type_ids_size hex: = " + type_ids_size.hex());
            dexCache.put("type_ids_size",type_ids_size);

            //type_ids_off
            ByteString type_ids_off = readByteString(bufferedSource,4);
            //输出16进制
            log("type_ids_off hex: = " + type_ids_off.hex());
            dexCache.put("type_ids_off",type_ids_off);

            //proto_ids_size
            ByteString proto_ids_size = readByteString(bufferedSource,4);
            //输出16进制
            log("proto_ids_size hex: = " + proto_ids_size.hex());
            dexCache.put("proto_ids_size",proto_ids_size);

            //proto_ids_off
            ByteString proto_ids_off = readByteString(bufferedSource,4);
            //输出16进制
            log("proto_ids_off hex: = " + proto_ids_off.hex());
            dexCache.put("proto_ids_off",proto_ids_off);

            //field_ids_size
            ByteString field_ids_size = readByteString(bufferedSource,4);
            //输出16进制
            log("field_ids_size hex: = " + field_ids_size.hex());
            dexCache.put("field_ids_size",field_ids_size);

            //field_ids_off
            ByteString field_ids_off = readByteString(bufferedSource,4);
            //输出16进制
            log("field_ids_off hex: = " + field_ids_off.hex());
            dexCache.put("field_ids_off",field_ids_off);

            //method_ids_size
            ByteString method_ids_size = readByteString(bufferedSource,4);
            //输出16进制
            log("method_ids_size hex: = " + method_ids_size.hex());
            dexCache.put("method_ids_size",method_ids_size);

            //method_ids_off
            ByteString method_ids_off = readByteString(bufferedSource,4);
            //输出16进制
            log("method_ids_off hex: = " + method_ids_off.hex());
            dexCache.put("method_ids_off",method_ids_off);

            //class_defs_size
            ByteString class_defs_size = readByteString(bufferedSource,4);
            //输出16进制
            log("class_defs_size hex: = " + class_defs_size.hex());
            dexCache.put("class_defs_size",class_defs_size);

            //class_defs_off
            ByteString class_defs_off = readByteString(bufferedSource,4);
            //输出16进制
            log("class_defs_off hex: = " + class_defs_off.hex());
            dexCache.put("class_defs_off",class_defs_off);

            //data_size
            ByteString data_size = readByteString(bufferedSource,4);
            //输出16进制
            log("data_size hex: = " + data_size.hex());
            dexCache.put("data_size",data_size);

            //data_off
            ByteString data_off = readByteString(bufferedSource,4);
            //输出16进制
            log("data_off hex: = " + data_off.hex());
            dexCache.put("data_off",method_ids_off);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void dexMapItems(InputStream open) {
        BufferedSource bufferedSource = Okio.buffer(Okio.source(open));
        try {

            log("map list ---------------------start-----------");
            //572：header区中map_off的值，根据map_off可直接定位到map_list所在的区域
            int mapOff = hex2int("map_off");
            bufferedSource.skip(mapOff);
            //mapItems大小
            ByteString byteString = readByteString(bufferedSource, 4);
            log("map size hex : = "+byteString.hex());
            log("map size : = "+buildBuffer(byteString).readIntLe());

            //map_item
            ByteString map_item = readByteString(bufferedSource, 13*(2+2+4+4));
            log("map_item : = "+map_item.hex());

            Buffer buffer = buildBuffer(map_item);
            for (int i = 0; i < 13; i++) {
                short type = buffer.readShortLe();
                short unused = buffer.readShortLe();
                int size = buffer.readIntLe();
                int offset = buffer.readIntLe();
                log("type: = " + type);
                log("unused: = " + unused);
                log("size: = " + size);
                log("offset: = " + offset);
            }

            log("map list ---------------------ebd-----------");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * @param open
     */
    private static void dexStringIds(InputStream open) {
        BufferedSource bufferedSource = Okio.buffer(Okio.source(open));
        try {
            log("string ids ---------------------start-----------");
            int stringIdsSize = hex2int("string_ids_size");
            log("string_ids_size : = " + stringIdsSize);

            //移动到string off处
            bufferedSource.skip(hex2int("string_ids_off"));
            ArrayList<Integer> list = new ArrayList<>();
            //读取stringIdsSize个stringids
            for (int i = 0; i < stringIdsSize; i++) {
                ByteString byteString = readByteString(bufferedSource, 4);
                log("stringIdOffset hex : = " + byteString.hex());
                list.add(buildBuffer(byteString).readIntLe());
//                log("stringIdOffset = " + buildBuffer(byteString).readIntLe());
            }
            dexStringIdsCache.put("string_ids",list);
            log("string ids ---------------------end-----------");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static HashMap<Integer, String> readStringIds(AssetManager assetManager) throws IOException {

        log("string ids ---------------------start-----------");
        ArrayList<Integer> string_ids = dexStringIdsCache.get("string_ids");
        HashMap<Integer, String> hashMap = new HashMap<Integer, String>();
        if(string_ids != null) {
            BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
            bufferedSource.skip(string_ids.get(0));
            Buffer buffer = new Buffer();
            buffer.writeAll(bufferedSource);

//            int leb128 = readUnsignedLeb128(buffer);
//            log("string_date = " + buffer.readByteString().hex());
//            log("string leb128 = " + leb128);
//            String decode = decode(buffer, new char[leb128]);
//            log("key： = " + decode);
            for (int i = 0; i < string_ids.size(); i++) {

                //读LEB 128,表示字符串长度
                int leb128 = Utils.readUnsignedLeb128(buffer);
                //解析真正的字符串
                String decode = Utils.decode(buffer, new char[leb128]);
                log("key： = " + decode);
                hashMap.put(i, decode);
            }
            log("string ids ---------------------end-----------");
        }
        return hashMap;
    }

    private static HashMap<Integer, String> readTypesIds(AssetManager assetManager) throws IOException {

        log("types ids ---------------------start-----------");

        BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
        HashMap<Integer, String> hashMap = new HashMap<Integer, String>();

        int typesIdsSize = hex2int("type_ids_size");
        log("type_ids_size : = " + typesIdsSize);

        //移动到string off处
        bufferedSource.skip(hex2int("type_ids_off"));

        for (int i = 0; i < typesIdsSize; i++) {
            ByteString byteString = readByteString(bufferedSource, 4);
            //type占4个字节
            int readIntle = buildBuffer(byteString).readIntLe();
            //从字符串区域中获取type对应的字符串
            String stringByOffs = getStringByOffs(readIntle);
            log("key: = " + byteString.hex() + " = " + stringByOffs);
            hashMap.put(i,stringByOffs);
        }


        log("types ids ---------------------end-----------");
        return hashMap;
    }

    /**
     * 函数原型
     * @param assetManager
     * @return
     * @throws IOException
     */
    private static HashMap<Integer, String> readProtosIds(AssetManager assetManager) throws IOException {

        log("proto ids ---------------------start-----------");

        BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
        HashMap<Integer, String> hashMap = new HashMap<Integer, String>();

        int protoIdsSize = hex2int("proto_ids_size");
        log("proto_ids_size : = " + protoIdsSize);

        //移动到string off处
        bufferedSource.skip(hex2int("proto_ids_off"));

        for (int i = 0; i < protoIdsSize; i++) {
            ByteString shorty_idx = readByteString(bufferedSource, 4);
            ByteString return_type_idx = readByteString(bufferedSource, 4);
            //参数地址
            ByteString parameter_off = readByteString(bufferedSource, 4);
            //从字符串区域中获取type对应的字符串
            String shortyString = getStringByOffs(buildBuffer(shorty_idx).readIntLe());
            String returnTypeString = getStringByOffs(buildBuffer(return_type_idx).readIntLe());

            log("shorty_idx: hex="+shorty_idx.hex() + "   value = " + shortyString);
            log("return_type_idx: hex="+return_type_idx.hex() + "   value = " + returnTypeString);

            // >0表示有参数
            int params_idx = buildBuffer(parameter_off).readIntLe();
            List<String> strings = null;
            if(params_idx > 0) {
                strings = readParams(assetManager, params_idx);
                log("parameter_off: hex="+parameter_off.hex() + "   value = " + strings);
            }
            String format = String.format("%s","%s","%s",shortyString,returnTypeString,strings == null ? "" : strings);
            hashMap.put(i,format);
        }

        return hashMap;
    }

    private static List<String> readParams(AssetManager assetManager,int offset) throws IOException {
        BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
        List<String> result = new ArrayList<>();
        bufferedSource.skip(offset);
        //第一个是参数个数
        int count = bufferedSource.readIntLe();
        for (int i = 0; i < count; i++) {
            //读取参数类型
            int i1 = bufferedSource.readShortLe();
            result.add(getTypeByOffs(i1));
        }
        return result;
    }

    private static void readFieldIds(AssetManager assetManager) throws IOException {
        log("field ids ---------------------start-----------");

        BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
        HashMap<Integer, String> hashMap = new HashMap<Integer, String>();

        int fieldIdsSize = hex2int("field_ids_size");
        log("field_ids_size : = " + fieldIdsSize);

        //移动到string off处
        bufferedSource.skip(hex2int("field_ids_off"));
        //循环读取fieldIdsSize个field
        for (int i = 0; i < fieldIdsSize; i++) {
            ByteString class_idx = readByteString(bufferedSource, 2);
            ByteString type_idx = readByteString(bufferedSource, 2);
            ByteString name_idx = readByteString(bufferedSource, 4);
            //从字符串区域中获取type对应的字符串

            String classString = getTypeByOffs(buildBuffer(class_idx).readShortLe());
            String typeString = getTypeByOffs(buildBuffer(type_idx).readShortLe());
            String nameString = getStringByOffs(buildBuffer(name_idx).readIntLe());

            log("class_idx: hex="+class_idx.hex() + "   value = " + classString);
            log("type_idx: hex="+type_idx.hex() + "   value = " + typeString);
            log("name_idx: hex="+name_idx.hex() + "   value = " + nameString);
        }
    }

    /**
     * 方法解析
     * @param assetManager
     * @return
     * @throws IOException
     */
    private static HashMap<Integer, String> readMethodIds(AssetManager assetManager) throws IOException {
        log("method ids ---------------------start-----------");

        BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
        HashMap<Integer, String> hashMap = new HashMap<Integer, String>();

        int size = hex2int("method_ids_size");
        log("method_ids_size : = " + size);

        //移动到string off处
        bufferedSource.skip(hex2int("method_ids_off"));
        //循环读取fieldIdsSize个field
        for (int i = 0; i < size; i++) {
            ByteString class_idx = readByteString(bufferedSource, 2);
            ByteString proto_idx = readByteString(bufferedSource, 2);
            ByteString name_idx = readByteString(bufferedSource, 4);
            //从字符串区域中获取type对应的字符串

            String classString = getTypeByOffs(buildBuffer(class_idx).readShortLe());
            String protoString = getProtoByOffs(buildBuffer(proto_idx).readShortLe());
            String nameString = getStringByOffs(buildBuffer(name_idx).readIntLe());

            log("class_idx: hex="+class_idx.hex() + "   value = " + classString);
            log("proto_idx: hex="+proto_idx.hex() + "   value = " + protoString);
            log("name_idx: hex="+name_idx.hex() + "   value = " + nameString);
            String format = String.format("%s","%s","%s",classString,protoString,nameString);
            hashMap.put(i,format);
        }
        return hashMap;
    }

    private static HashMap<Integer, String> readClassIds(AssetManager assetManager) throws IOException {
        log("class def ids ---------------------start-----------");

        BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
        HashMap<Integer, String> hashMap = new HashMap<Integer, String>();

        int size = hex2int("class_defs_size");
        log("class_defs_size : = " + size);

        //移动到string off处
        bufferedSource.skip(hex2int("class_defs_off"));
        //循环读取fieldIdsSize个field
        for (int i = 0; i < size; i++) {
            ByteString class_idx = readByteString(bufferedSource, 4);
            ByteString access_flags = readByteString(bufferedSource, 4);
            ByteString superclass_idx = readByteString(bufferedSource, 4);
            ByteString iterfaces_off = readByteString(bufferedSource, 4);
            ByteString source_file_idx = readByteString(bufferedSource, 4);
            ByteString annotation_off = readByteString(bufferedSource, 4);
            ByteString class_data_off = readByteString(bufferedSource, 4);
            ByteString static_value_off = readByteString(bufferedSource, 4);


            //从字符串区域中获取type对应的字符串
            String classString = getTypeByOffs(buildBuffer(class_idx).readIntLe());
            String superClassString = getTypeByOffs(buildBuffer(superclass_idx).readIntLe());
            String sourceFileString = getStringByOffs(buildBuffer(source_file_idx).readIntLe());


            log("class_idx: hex:"+class_idx.hex() + ",value:" + classString);
            log("access_flags: hex:"+access_flags.hex());
            log("superclass_idx: hex:"+superclass_idx.hex() + ",value:" + superClassString);
            log("iterfaces_off: hex:"+iterfaces_off.hex());
            log("source_file_idx: hex:"+source_file_idx.hex() + ",value:" + sourceFileString);
            log("annotation_off: hex:"+annotation_off.hex());
            log("class_data_off: hex:"+class_data_off.hex());
            log("static_value_off: hex:"+static_value_off.hex());

            int inter_off = buildBuffer(iterfaces_off).readShortLe();
            if(inter_off > 0) {
                interfaceParse(assetManager,inter_off);
            }

            int class_data_off_index = buildBuffer(class_data_off).readIntLe();
            if(class_data_off_index > 0) {
                classDataParse(assetManager,class_data_off_index);
            }
        }
        return hashMap;
    }

    private static void interfaceParse(AssetManager assetManager,int off) throws IOException {
        log("interface_off ids ---------------------start-----------");
        BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
        bufferedSource.skip(off);
        ByteString interfaceStr = readByteString(bufferedSource, 4);
        int interfaceSize = buildBuffer(interfaceStr).readIntLe();
        log("interfaceStr = "+interfaceStr + ",size = " + interfaceSize);
        for (int i = 0; i < interfaceSize; i++) {
            ByteString interfaceIndexStr = readByteString(bufferedSource, 4);
            int interfaceIndex = buildBuffer(interfaceIndexStr).readIntLe();
            String str = getTypeByOffs(interfaceIndex);
            log("interface_off: dex="+interfaceIndexStr + ",size="+interfaceIndex + ",value="+str);
        }

    }

    /**
     * class_data_item的结构
     struct class_data_item{
         uleb128 static_fields_size;     //静态字段
         uleb128 instance_fields_size;   //实例字段
         uleb128 direct_methods_size;    //直接方法（private或者构造方法）
         uleb128 virtual_methods_size;   //虚方法（非private、static、final，非构造方法）
         encoded_field static_fields[static_fields_size];        //静态字段
         encoded_field instance_fields[instance_fields_size];    //实例字段
         encoded_method direct_methods[direct_method_size];      //直接方法
         encoded_method virtual_methods[virtual_methods_size];   //虚方法
     }

     struct encoded_field{
         uleb128 filed_idx_diff;
         uleb128 access_flags;
     }

     struct encoded_method{
         uleb128 method_idx_diff;
         uleb128 access_flags;
         uleb128 code_off;
     }
     * @param assetManager
     * @param off
     * @throws IOException
     */
    private static void classDataParse(AssetManager assetManager,int off) throws IOException {
        log("class_data ids ---------------------start-----------");
        BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
        bufferedSource.skip(off);
        Buffer buffer = new Buffer();
        buffer.writeAll(bufferedSource);


        log("staticFieldsSize hex:"+buffer.toString());
        int staticFieldsSize = Utils.readUnsignedLeb128(buffer);
        log("size="+staticFieldsSize);

        log("instanceFieldsSize hex:"+buffer.toString());
        int instanceFieldsSize = Utils.readUnsignedLeb128(buffer);
        log("size="+instanceFieldsSize);

        log("staticFieldsSize hex:"+buffer.toString());
        int directMethodsSize = Utils.readUnsignedLeb128(buffer);
        log("size="+directMethodsSize);

        log("staticFieldsSize hex:"+buffer.toString());
        int virtualMethodsSize = Utils.readUnsignedLeb128(buffer);
        log("size="+virtualMethodsSize);




        /**
         struct encoded_field{
             uleb128 filed_idx_diff;
             uleb128 access_flags;
         }
         */
        int fieldIndex = 0;
        for (int i = 0; i < staticFieldsSize; i++) {
            log("encoded_field hex:"+buffer.toString());
            fieldIndex += Utils.readUnsignedLeb128(buffer); //field index off
            int accessFlags = Utils.readUnsignedLeb128(buffer);

            log("field index diff = " + fieldIndex);
            log("accessFlags = " + accessFlags);
        }

        fieldIndex = 0;
        for (int i = 0; i < instanceFieldsSize; i++) {
            log("encoded_field hex:"+buffer.toString());
            fieldIndex += Utils.readUnsignedLeb128(buffer); //field index off
            int accessFlags = Utils.readUnsignedLeb128(buffer);

            log("field index diff = " + fieldIndex);
            log("accessFlags = " + accessFlags);
        }

        /**
         struct encoded_method{
             uleb128 method_idx_diff;
             uleb128 access_flags;
             uleb128 code_off;
         }
         */
        int methodIndex = 0;
        for (int i = 0; i < directMethodsSize; i++) {
            log("encoded_method hex:"+buffer.toString());
            methodIndex += Utils.readUnsignedLeb128(buffer); //对应method字典中的索引
            int accessFlags = Utils.readUnsignedLeb128(buffer);
            int codeOff = Utils.readUnsignedLeb128(buffer);

            log("methodIndex:" + methodIndex);
            log("methodIndexString:" + getMethodByOff(methodIndex));
            log("accessFlags:" + accessFlags);
            log("codeOff:" + codeOff);

            codeParse(assetManager,codeOff);
        }

        methodIndex = 0;
        for (int i = 0; i < virtualMethodsSize; i++) {
            log("encoded_method hex:"+buffer.toString());
            methodIndex += Utils.readUnsignedLeb128(buffer); //对应method字典中的索引
            int accessFlags = Utils.readUnsignedLeb128(buffer);
            int codeOff = Utils.readUnsignedLeb128(buffer);

            log("methodIndex:" + methodIndex);
            log("methodIndexString:" + getMethodByOff(methodIndex));
            log("accessFlags:" + accessFlags);
            log("codeOff:" + codeOff);

            codeParse(assetManager,codeOff);
        }
    }

    /**

     struct code_item {
         ushort registers_size;//本段代码使用到的寄存器数目
         ushort ins_size;      //传入当前method的参数数量，后面的结果中默认的构造方法中这个值是1，原因是有个this，静态方法没this
         ushort outs_size;     //本段代码调用其它method时需要的参数个数
         ushort tries_size;    //代码块中异常处理的数量，结构为try_item
         uint debug_info_off;  //偏移地址，指向本段代码的debug信息存放位置，是一个debug_info_item结构
         uint insns_size;      //指令列表的大小，以16-bit为单位。insns是instructions的缩写
         ushort insns[insns_size];   //指令列表
         ushort paddding;                      // optional，值为0，用于对齐字节
         try_item tries[tyies_size];           // optional，用于处理java中的exception，常见的语法有try catch
         encoded_catch_handler_list handlers;  // optional，用于处理java中的exception，常见的语法有try catch
     }

     * @param assetManager
     * @param off
     * @throws IOException
     */
    private static void codeParse(AssetManager assetManager,int off) throws IOException {
        log("code_off ---------------------start-----------");
        BufferedSource bufferedSource = Okio.buffer(Okio.source(assetManager.open(DEX_NAME)));
        bufferedSource.skip(off);

        ByteString registers_size_str = readByteString(bufferedSource, 2);
        ByteString ins_size_str = readByteString(bufferedSource, 2);
        ByteString outs_size_str = readByteString(bufferedSource, 2);
        ByteString tries_size_str = readByteString(bufferedSource, 2);
        ByteString debug_info_off_str = readByteString(bufferedSource, 4);
        ByteString insns_size_str = readByteString(bufferedSource, 4);
        ByteString insns_str = readByteString(bufferedSource, 2);
        ByteString paddding_str = readByteString(bufferedSource, 2);

        short registers_size = buildBuffer(registers_size_str).readShortLe();
        short ins_size = buildBuffer(ins_size_str).readShortLe();
        short outs_size = buildBuffer(outs_size_str).readShortLe();
        short tries_size = buildBuffer(tries_size_str).readShortLe();
        short debug_info_off = buildBuffer(debug_info_off_str).readShortLe();
        short insns_size = buildBuffer(insns_size_str).readShortLe();
        short insns = buildBuffer(insns_str).readShortLe();
        short paddding = buildBuffer(paddding_str).readShortLe();

        log("registers_size_str hex:" + registers_size_str.hex() + ",registers_size="+registers_size);
        log("ins_size_str hex:" + ins_size_str.hex() + ",ins_size="+ins_size);
        log("outs_size_str hex:" + outs_size_str.hex() + ",outs_size="+outs_size);
        log("tries_size_str hex:" + tries_size_str.hex() + ",tries_size="+tries_size);
        log("debug_info_off_str hex:" + debug_info_off_str.hex() + ",debug_info_off="+debug_info_off);
        log("insns_size_str hex:" + insns_size_str.hex() + ",insns_size="+insns_size);
        log("insns_str hex:" + insns_str.hex() + ",insns="+insns);
        log("paddding_str hex:" + paddding_str.hex() + ",paddding="+paddding);

    }
    private static String getStringByOffs(int offset) {
        if(stringCache != null) {
            return stringCache.get(offset);
        }
        return "";
    }

    private static String getTypeByOffs(int offset) {
        if(typeCache != null)
            return typeCache.get(offset);
        return "";
    }

    private static String getProtoByOffs(int offset) {
        if(protoCache != null)
            return protoCache.get(offset);
        return "";
    }

    private static String getMethodByOff(int offset) {
        if(methodCache != null)
            return methodCache.get(offset);
        return "";
    }

    private static int hex2int(String key) {
        return buildBuffer(dexCache.get(key)).readIntLe();
    }

    private static Buffer buildBuffer(ByteString str) {
        byte[] bytes = str.toByteArray();
        Buffer buffer = new Buffer();
        buffer.write(bytes);
        return buffer;
    }

    private static ByteString readByteString(BufferedSource bufferedSource,int count) throws IOException {
        //读取magic，占用8个字节，读取开始地址的8个字节即可
        byte[] bytes = bufferedSource.readByteArray(count);
        Buffer buffer = new Buffer();
        buffer.write(bytes);
        return buffer.readByteString();
    }

    private static void log(String msg) {
        Log.i("DexParse--->",msg);
    }

}
