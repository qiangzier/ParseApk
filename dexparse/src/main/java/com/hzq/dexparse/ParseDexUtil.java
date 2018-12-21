package com.hzq.dexparse;

import com.hzq.dexparse.struct.ClassDataItem;
import com.hzq.dexparse.struct.ClassDefItem;
import com.hzq.dexparse.struct.CodeItem;
import com.hzq.dexparse.struct.EncodedField;
import com.hzq.dexparse.struct.EncodedMethod;
import com.hzq.dexparse.struct.FieldIdsItem;
import com.hzq.dexparse.struct.HeaderType;
import com.hzq.dexparse.struct.MethodIdsItem;
import com.hzq.dexparse.struct.ProtoIdsItem;
import com.hzq.dexparse.struct.StringDataItem;
import com.hzq.dexparse.struct.StringIdsItem;
import com.hzq.dexparse.struct.TypeIdsItem;
import com.hzq.dexparse.utils.Utils;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by hezhiqiang on 2018/12/19.
 */

public class ParseDexUtil {

    public static HeaderType headerType;
    public static List<StringDataItem> stringDataItems;
    public static List<TypeIdsItem> typeIdsItems;
    public static List<ProtoIdsItem> protoIdsItems;
    public static List<FieldIdsItem> fieldIdsItems;
    public static List<MethodIdsItem> methodIdsItems;
    public static void main(byte[] dexs) {
        headerType = parseHeader(dexs);
        stringDataItems = parseStringDataItem(dexs);
        typeIdsItems = parseTypeIdsItem(dexs);
        protoIdsItems = parseProtoIds(dexs);
        fieldIdsItems = parseFieldIds(dexs);
        methodIdsItems = parseMethodIds(dexs);
        parseClassData(dexs);
    }

    /**
     * 解析Dex Header部分
     */
    public static HeaderType parseHeader(byte[] byteSrc) {
        Utils.log("header parse start------------------->");
        HeaderType headerType = new HeaderType();

        //解析magic
        headerType.magic = Utils.copyByte(byteSrc,0,8);

        //解析checksum
        byte[] checksum = Utils.copyByte(byteSrc,8,4);
        headerType.checksum = Utils.byte2int(checksum);

        //解析signature
        byte[] signature = Utils.copyByte(byteSrc,12,20);
        headerType.signature = signature;

        //解析file_size
        byte[] fileSizeByte = Utils.copyByte(byteSrc, 32, 4);
        headerType.file_size = Utils.byte2int(fileSizeByte);

        //解析header_size
        byte[] headerSizeByte = Utils.copyByte(byteSrc, 36, 4);
        headerType.header_size = Utils.byte2int(headerSizeByte);

        //解析endian_tag
        byte[] endianTagByte = Utils.copyByte(byteSrc, 40, 4);
        headerType.endian_tag = Utils.byte2int(endianTagByte);

        //解析link_size
        byte[] linkSizeByte = Utils.copyByte(byteSrc, 44, 4);
        headerType.link_size = Utils.byte2int(linkSizeByte);

        //解析link_off
        byte[] linkOffByte = Utils.copyByte(byteSrc, 48, 4);
        headerType.link_off = Utils.byte2int(linkOffByte);

        //解析map_off
        byte[] mapOffByte = Utils.copyByte(byteSrc, 52, 4);
        headerType.map_off = Utils.byte2int(mapOffByte);

        //解析string_ids_size
        byte[] stringIdsSizeByte = Utils.copyByte(byteSrc, 56, 4);
        headerType.string_ids_size = Utils.byte2int(stringIdsSizeByte);

        //解析string_ids_off
        byte[] stringIdsOffByte = Utils.copyByte(byteSrc, 60, 4);
        headerType.string_ids_off = Utils.byte2int(stringIdsOffByte);

        //解析type_ids_size
        byte[] typeIdsSizeByte = Utils.copyByte(byteSrc, 64, 4);
        headerType.type_ids_size = Utils.byte2int(typeIdsSizeByte);

        //解析type_ids_off
        byte[] typeIdsOffByte = Utils.copyByte(byteSrc, 68, 4);
        headerType.type_ids_off = Utils.byte2int(typeIdsOffByte);

        //解析proto_ids_size
        byte[] protoIdsSizeByte = Utils.copyByte(byteSrc, 72, 4);
        headerType.proto_ids_size = Utils.byte2int(protoIdsSizeByte);

        //解析proto_ids_off
        byte[] protoIdsOffByte = Utils.copyByte(byteSrc, 76, 4);
        headerType.proto_ids_off = Utils.byte2int(protoIdsOffByte);

        //解析field_ids_size
        byte[] fieldIdsSizeByte = Utils.copyByte(byteSrc, 80, 4);
        headerType.field_ids_size = Utils.byte2int(fieldIdsSizeByte);

        //解析field_ids_off
        byte[] fieldIdsOffByte = Utils.copyByte(byteSrc, 84, 4);
        headerType.field_ids_off = Utils.byte2int(fieldIdsOffByte);

        //解析method_ids_size
        byte[] methodIdsSizeByte = Utils.copyByte(byteSrc, 88, 4);
        headerType.method_ids_size = Utils.byte2int(methodIdsSizeByte);

        //解析method_ids_off
        byte[] methodIdsOffByte = Utils.copyByte(byteSrc, 92, 4);
        headerType.method_ids_off = Utils.byte2int(methodIdsOffByte);

        //解析class_defs_size
        byte[] classDefsSizeByte = Utils.copyByte(byteSrc, 96, 4);
        headerType.class_defs_size = Utils.byte2int(classDefsSizeByte);

        //解析class_defs_off
        byte[] classDefsOffByte = Utils.copyByte(byteSrc, 100, 4);
        headerType.class_defs_off = Utils.byte2int(classDefsOffByte);

        //解析data_size
        byte[] dataSizeByte = Utils.copyByte(byteSrc, 104, 4);
        headerType.data_size = Utils.byte2int(dataSizeByte);

        //解析data_off
        byte[] dataOffByte = Utils.copyByte(byteSrc, 108, 4);
        headerType.data_off = Utils.byte2int(dataOffByte);

        Utils.log("header:"+headerType);
        return headerType;
    }

    /**
     * 解析string偏移地址
     * @param src
     * @return
     */
    public static List<StringIdsItem> parseStringIds(byte[] src) {
        List<StringIdsItem> result = new ArrayList<>();
        int idSize = StringIdsItem.getSize();
        int countIds = headerType.string_ids_size;
        for (int i = 0; i < countIds; i++) {
            result.add(parseStringIdsItem(Utils.copyByte(src,headerType.string_ids_off+i*idSize,idSize)));
        }
        Utils.log("string size = " + result.size());
        return result;
    }

    private static StringIdsItem parseStringIdsItem(byte[] srcByte) {
        StringIdsItem idsItem = new StringIdsItem();
        byte[] idsByte = Utils.copyByte(srcByte,0,4);
        idsItem.string_data_off = Utils.byte2int(idsByte);
        return idsItem;
    }

    public static List<StringDataItem> parseStringDataItem(byte[] src) {
        Utils.log("string ids parse start------------------->");
        List<StringDataItem> list = new ArrayList<>();
        List<StringIdsItem> stringIdsItems = parseStringIds(src);
        if(stringIdsItems != null) {
            for (StringIdsItem stringIdsItem : stringIdsItems) {
                StringDataItem string = Utils.getString(src, stringIdsItem.string_data_off);
                Utils.log("string data = " + string.toString());
                list.add(string);
            }
        }
        return list;
    }

    /**
     * 解析type
     * @param src
     * @return
     */
    public static List<TypeIdsItem> parseTypeIdsItem(byte[] src) {
        Utils.log("type ids parse start------------------->");
        List<TypeIdsItem> list = new ArrayList<>();
        int idSize = TypeIdsItem.getSize();
        int count = headerType.type_ids_size;
        Utils.log("type ids size " + count);
        for (int i = 0; i < count; i++) {
            byte[] bytes = Utils.copyByte(src, headerType.type_ids_off + i * idSize, idSize);
            TypeIdsItem build = TypeIdsItem.build(Utils.copyByte(bytes, 0, 4));
            Utils.log("type data = " + build.toString() + ",value="+Utils.getStringByOff(stringDataItems,build.descriptor_idx));
            list.add(build);
        }
        return list;
    }

    /**
     * 解析函数原型 （返回值+参数列表）
     * @param src
     * @return
     */
    public static List<ProtoIdsItem> parseProtoIds(byte[] src) {
        Utils.log("proto ids parse start------------------->");
        List<ProtoIdsItem> lists = new ArrayList<>();
        int idSize = ProtoIdsItem.getSize();
        int count = headerType.proto_ids_size;
        Utils.log("proto data size = "+count);

        ProtoIdsItem item = null;
        for (int i = 0; i < count; i++) {
            byte[] bytes = Utils.copyByte(src, headerType.proto_ids_off + i * idSize, idSize);
            item = new ProtoIdsItem();
            byte[] shorty_idx = Utils.copyByte(bytes, 0, 4);
            byte[] return_type_idx = Utils.copyByte(bytes, 4, 4);
            byte[] parameters_off = Utils.copyByte(bytes, 8, 4);

            item.shorty_idx = Utils.byte2int(shorty_idx);
            item.return_type_idx = Utils.byte2int(return_type_idx);
            item.parameters_off = Utils.byte2int(parameters_off);

            item.shorty_str = Utils.getStringByOff(stringDataItems,item.shorty_idx);
            item.return_type_str = Utils.getStringByOff(stringDataItems,Utils.getTypeByOffset(typeIdsItems,item.return_type_idx));

            lists.add(item);
        }

        //解析参数
        for (ProtoIdsItem list : lists) {
            if(item.parameters_off > 0) {
                //解析size和size大小的list中内容
                byte[] sizeByte = Utils.copyByte(src,item.parameters_off,4);
                int size = Utils.byte2int(sizeByte);

                List<Short> typeIds = new ArrayList<>();
                List<String> paramsList = new ArrayList<>();
                for (int i = 0; i < size; i++) {
                    //占用两个字节
                    byte[] bytes = Utils.copyByte(src, item.parameters_off + 4 + 2 * i, 2);
                    typeIds.add(Utils.byte2Short(bytes));
                    int typeByOffset = Utils.getTypeByOffset(typeIdsItems, Utils.byte2Short(bytes));
                    String stringByOff = Utils.getStringByOff(stringDataItems, typeByOffset);
                    paramsList.add(stringByOff);
                }

                list.parameterCount = size;
                list.parametersTypeIdx = typeIds;
                list.parametersListStr = paramsList;
            }

            Utils.log("proto data = "+list.toString());
        }
        return lists;
    }

    /**
     * 解析属性
     * @param src
     * @return
     */
    public static List<FieldIdsItem> parseFieldIds(byte[] src) {
        Utils.log("field ids parse start------------------->");
        int idSize = FieldIdsItem.getSize();
        int count = headerType.field_ids_size;
        int offset = headerType.field_ids_off;
        Utils.log("field ids size " + count);
        List<FieldIdsItem> list = new ArrayList<>();
        FieldIdsItem item = null;
        for (int i = 0; i < count; i++) {
            item = new FieldIdsItem();
            byte[] bytes = Utils.copyByte(src, offset + i * idSize, idSize);
            byte[] classIdxByte = Utils.copyByte(bytes, 0, 2);
            byte[] typeIdxByte = Utils.copyByte(bytes, 2, 2);
            byte[] nameIdxByte = Utils.copyByte(bytes, 4, 4);

            item.class_idx = Utils.byte2Short(classIdxByte);
            item.type_idx = Utils.byte2Short(typeIdxByte);
            item.name_idx = Utils.byte2int(nameIdxByte);

            item.class_str = Utils.getStringByOff(stringDataItems,Utils.getTypeByOffset(typeIdsItems,item.class_idx));
            item.type_str = Utils.getStringByOff(stringDataItems,Utils.getTypeByOffset(typeIdsItems,item.type_idx));
            item.name_str = Utils.getStringByOff(stringDataItems,item.name_idx);

            Utils.log("field data = " + item.toString());
        }
        return list;
    }

    /**
     * 解析方法
     * @param src
     * @return
     */
    public static List<MethodIdsItem> parseMethodIds(byte[] src) {
        Utils.log("method ids parse start------------------->");
        List<MethodIdsItem> list = new ArrayList<>();
        int idSize = MethodIdsItem.getSize();
        int count = headerType.method_ids_size;
        int offset = headerType.method_ids_off;
        Utils.log("method ids size " + count);
        MethodIdsItem item = null;
        for (int i = 0; i < count; i++) {
            item = new MethodIdsItem();
            byte[] bytes = Utils.copyByte(src, offset + i * idSize, idSize);

            byte[] classIdxByte = Utils.copyByte(bytes, 0, 2);
            byte[] protoIdxByte = Utils.copyByte(bytes, 2, 2);
            byte[] nameIdxByte = Utils.copyByte(bytes, 4, 4);

            item.class_idx = Utils.byte2Short(classIdxByte);
            item.proto_idx = Utils.byte2Short(protoIdxByte);
            item.name_idx = Utils.byte2int(nameIdxByte);

            item.class_str = Utils.getStringByOff(stringDataItems,Utils.getTypeByOffset(typeIdsItems,item.class_idx));
            item.name_str = Utils.getStringByOff(stringDataItems,item.name_idx);
            item.proto_str = "fun " + item.name_str + Utils.getProtoByOffset(protoIdsItems,item.proto_idx);

//            Utils.log("method data = " + item.toString());
            Utils.log("method data = " + item.proto_str);
        }
        return list;
    }

    public static List<ClassDefItem> parseClassData(byte[] src) {
        List<ClassDefItem> list = new ArrayList<>();
        int idSize = ClassDefItem.getSize();
        int count = headerType.class_defs_size;
        int offset = headerType.class_defs_off;
        Utils.log("class def parse start------------------->");
        Utils.log("class def size " + count);
        ClassDefItem item = null;
        for (int i = 0; i < count; i++) {
            byte[] srcByte = Utils.copyByte(src, offset + i * idSize, idSize);
            item = new ClassDefItem();
            byte[] classIdxByte = Utils.copyByte(srcByte, 0, 4);
            item.class_idx = Utils.byte2int(classIdxByte);
            item.class_str = Utils.getStringByOff(stringDataItems,Utils.getTypeByOffset(typeIdsItems,item.class_idx));

            byte[] accessFlagsByte = Utils.copyByte(srcByte, 4, 4);
            item.access_flags = Utils.byte2int(accessFlagsByte);

            byte[] superClassIdxByte = Utils.copyByte(srcByte, 8, 4);
            item.superclass_idx = Utils.byte2int(superClassIdxByte);
            item.superclass_str = Utils.getStringByOff(stringDataItems,Utils.getTypeByOffset(typeIdsItems,item.superclass_idx));

            //这里如果class没有interfaces的话，这里就为0
            byte[] iterfacesOffByte = Utils.copyByte(srcByte, 12, 4);
            item.iterfaces_off = Utils.byte2int(iterfacesOffByte);
            /**
             struct type_list {
                uint size,
                ushort type_idx[size]
             }
             */
            if(item.iterfaces_off > 0) {
                byte[] sizeBytes = Utils.copyByte(src, item.iterfaces_off, 4);
                int size = Utils.byte2int(sizeBytes);
                List<Short> interfaceIndex = new ArrayList<>();
                List<String> interfaceList = new ArrayList<>();
                for (int j = 0; j < size; j++) {
                    byte[] bytes = Utils.copyByte(src, item.iterfaces_off + 4 + j * 2, 2);
                    short index = Utils.byte2Short(bytes);
                    interfaceIndex.add(index);
                    interfaceList.add(Utils.getStringByOff(stringDataItems,Utils.getTypeByOffset(typeIdsItems,index)));
                }
                item.interfaceIndex = interfaceIndex;
                item.interfaceList = interfaceList;
            }

            //如果此项信息缺失，值为0xFFFFFF
            byte[] sourceFileIdxByte = Utils.copyByte(srcByte, 16, 4);
            item.source_file_idx = Utils.byte2int(sourceFileIdxByte);
            item.source_file_str = Utils.getStringByOff(stringDataItems,item.source_file_idx);

            byte[] annotationsOffByte = Utils.copyByte(srcByte, 20, 4);
            item.annotations_off = Utils.byte2int(annotationsOffByte);


            byte[] classDataOffByte = Utils.copyByte(srcByte, 24, 4);
            item.class_data_off = Utils.byte2int(classDataOffByte);
            ClassDataItem classDataItem = parseClassData(src, item.class_data_off);
            item.classDataItem = classDataItem;

            byte[] staticValueOffByte = Utils.copyByte(srcByte, 28, 4);
            item.static_value_off = Utils.byte2int(staticValueOffByte);

            Utils.log("class def data = " + item.toString());
            list.add(item);
        }

        return list;
    }

    public static ClassDataItem parseClassData(byte[] src,int offset) {
        ClassDataItem item = new ClassDataItem();
        byte[] bytes = Utils.copyByte(src, offset, 16);
        Utils.log("class_data_item hex=" + Utils.bytesToHexString(bytes));
        for (int i = 0; i < 4; i++) {
            byte[] byteAry = Utils.readUnsignedLeb128(src, offset);
            offset += byteAry.length;
            int size = 0;
            if(byteAry.length == 1) {
                size = byteAry[0];
            } else if(byteAry.length == 2) {
                size = Utils.byte2Short(byteAry);
            } else if(byteAry.length == 4) {
                size = Utils.byte2int(byteAry);
            }

            if(i == 0) {
                item.static_fields_size = size;
            } if(i == 1) {
                item.instance_fields_size = size;
            } if(i == 2) {
                item.direct_methods_size = size;
            } if(i == 3) {
                item.virtual_methods_size = size;
            }

        }

        /**
         struct encoded_field{
             uleb128 filed_idx_diff;
             uleb128 access_flags;
         }
         */
        //解析static_fields数字
        EncodedField[] staticFieldAry = new EncodedField[item.static_fields_size];
        for (int i = 0; i < item.static_fields_size; i++) {
            EncodedField field = new EncodedField();
            field.filed_idx_diff = Utils.readUnsignedLeb128(src,offset);
            offset += field.filed_idx_diff.length;
            field.access_flags = Utils.readUnsignedLeb128(src,offset);
            offset += field.access_flags.length;
            staticFieldAry[i] = field;
        }

        // 解析instance_fields数组
        EncodedField[] instanceFieldAry = new EncodedField[item.instance_fields_size];
        for (int i = 0; i < item.instance_fields_size; i++) {
            EncodedField field = new EncodedField();
            field.filed_idx_diff = Utils.readUnsignedLeb128(src,offset);
            offset += field.filed_idx_diff.length;
            field.access_flags = Utils.readUnsignedLeb128(src,offset);
            offset += field.access_flags.length;
            instanceFieldAry[i] = field;
        }

        /**
         struct encoded_method{
             uleb128 method_idx_diff;
             uleb128 access_flags;
             uleb128 code_off;
         }
         */

        //解析static_methods
        EncodedMethod[] diectMethodAry = new EncodedMethod[item.direct_methods_size];
        for (int i = 0; i < item.direct_methods_size; i++) {
            EncodedMethod method = new EncodedMethod();
            method.method_idx_diff = Utils.readUnsignedLeb128(src,offset);
            offset += method.method_idx_diff.length;

            method.access_flags = Utils.readUnsignedLeb128(src,offset);
            offset += method.access_flags.length;

            method.code_off = Utils.readUnsignedLeb128(src,offset);
            offset += method.code_off.length;
            method.codeItem = parseCodeItem(src,Utils.decodeUleb128(method.code_off));

            diectMethodAry[i] = method;
        }


        //解析instance_methods
        EncodedMethod[] virtualMethodAry = new EncodedMethod[item.virtual_methods_size];
        for (int i = 0; i < item.virtual_methods_size; i++) {
            EncodedMethod method = new EncodedMethod();
            method.method_idx_diff = Utils.readUnsignedLeb128(src,offset);
            offset += method.method_idx_diff.length;

            method.access_flags = Utils.readUnsignedLeb128(src,offset);
            offset += method.access_flags.length;

            method.code_off = Utils.readUnsignedLeb128(src,offset);
            offset += method.code_off.length;

            method.codeItem = parseCodeItem(src,Utils.decodeUleb128(method.code_off));

            virtualMethodAry[i] = method;
        }
        item.static_fields = staticFieldAry;
        item.instance_fields = instanceFieldAry;
        item.direct_methods = diectMethodAry;
        item.virtual_methods = virtualMethodAry;
        return item;
    }

    //解析代码内容
    public static CodeItem parseCodeItem(byte[] src,int offset) {
        /**
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
         */
        CodeItem codeItem = new CodeItem();
        byte[] regByte = Utils.copyByte(src, offset, 2);
        codeItem.registers_size = Utils.byte2Short(regByte);
        codeItem.ins_size = Utils.byte2Short(Utils.copyByte(src,offset + 2,2));
        codeItem.outs_size = Utils.byte2Short(Utils.copyByte(src,offset + 4,2));
        codeItem.tries_size = Utils.byte2Short(Utils.copyByte(src,offset + 6,2));

        codeItem.debug_info_off = Utils.byte2int(Utils.copyByte(src,offset + 8,4));
        codeItem.insns_size = Utils.byte2int(Utils.copyByte(src,offset + 12,4));

        short[] insnsAry = new short[codeItem.insns_size];
        int aryOffset = offset + 16;
        for (int i = 0; i < codeItem.insns_size; i++) {
            insnsAry[i] = Utils.byte2Short(Utils.copyByte(src,aryOffset + i*2,2));
        }
        codeItem.insns = insnsAry;
        return codeItem;
    }
}
