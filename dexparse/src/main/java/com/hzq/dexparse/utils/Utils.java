package com.hzq.dexparse.utils;

import android.util.Log;

import com.hzq.dexparse.struct.MethodIdsItem;
import com.hzq.dexparse.struct.ProtoIdsItem;
import com.hzq.dexparse.struct.StringDataItem;
import com.hzq.dexparse.struct.TypeIdsItem;

import java.io.IOException;
import java.io.UTFDataFormatException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import okio.Buffer;

/**
 * Created by hezhiqiang on 2018/12/19.
 */

public class Utils {

    public static int byte2int(byte[] res) {
        int targets = (res[0] & 0xff) | ((res[1] << 8) & 0xff00)
                | ((res[2] << 24) >>> 8) | (res[3] << 24);
        return targets;
    }

    public static byte[] int2Byte(int integer) {
        int byteNum = (40 -Integer.numberOfLeadingZeros (integer < 0 ? ~integer : integer))/ 8;
        byte[] byteArray = new byte[4];

        for (int n = 0; n < byteNum; n++)
            byteArray[3 - n] = (byte) (integer>>> (n * 8));

        return (byteArray);
    }

    public static byte[] int2ByteLe(int value) {
        byte[] src = new byte[4];
        src[3] = (byte) ((value >> 24) & 0xFF);
        src[2] = (byte) ((value >> 16) & 0xFF);
        src[1] = (byte) ((value >> 8) & 0xFF);
        src[0] = (byte) (value & 0xFF);
        return src;
    }

    public static byte[] short2Byte(short number) {
        int temp = number;
        byte[] b = new byte[2];
        for (int i = 0; i < b.length; i++) {
            b[i] = new Integer(temp & 0xff).byteValue();//将最低位保存在最低位
            temp = temp >> 8; // 向右移8位
        }
        return b;
    }

    public static short byte2Short(byte[] b) {
        short s = 0;
        short s0 = (short) (b[0] & 0xff);
        short s1 = (short) (b[1] & 0xff);
        s1 <<= 8;
        s = (short) (s0 | s1);
        return s;
    }

    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv+" ");
        }
        return stringBuilder.toString();
    }

    public static char[] getChars(byte[] bytes) {
        Charset cs = Charset.forName ("UTF-8");
        ByteBuffer bb = ByteBuffer.allocate (bytes.length);
        bb.put (bytes);
        bb.flip ();
        CharBuffer cb = cs.decode (bb);
        return cb.array();
    }

    public static byte[] copyByte(byte[] src, int start, int len){
        if(src == null){
            return null;
        }
        if(start > src.length){
            return null;
        }
        if((start+len) > src.length){
            return null;
        }
        if(start<0){
            return null;
        }
        if(len<=0){
            return null;
        }
        byte[] resultByte = new byte[len];
        for(int i=0;i<len;i++){
            resultByte[i] = src[i+start];
        }
        return resultByte;
    }

    public static byte[] reverseBytes(byte[] bytess){
        byte[] bytes = new byte[bytess.length];
        for(int i=0;i<bytess.length;i++){
            bytes[i] = bytess[i];
        }
        if(bytes == null || (bytes.length % 2) != 0){
            return bytes;
        }
        int i = 0, len = bytes.length;
        while(i < (len/2)){
            byte tmp = bytes[i];
            bytes[i] = bytes[len-i-1];
            bytes[len-i-1] = tmp;
            i++;
        }
        return bytes;
    }

    public static String filterStringNull(String str){
        if(str == null || str.length() == 0){
            return str;
        }
        byte[] strByte = str.getBytes();
        ArrayList<Byte> newByte = new ArrayList<Byte>();
        for(int i=0;i<strByte.length;i++){
            if(strByte[i] != 0){
                newByte.add(strByte[i]);
            }
        }
        byte[] newByteAry = new byte[newByte.size()];
        for(int i=0;i<newByteAry.length;i++){
            newByteAry[i] = newByte.get(i);
        }
        return new String(newByteAry);
    }

    public static String getStringFromByteAry(byte[] srcByte, int start){
        if(srcByte == null){
            return "";
        }
        if(start < 0){
            return "";
        }
        if(start >= srcByte.length){
            return "";
        }
        byte val = srcByte[start];
        int i = 1;
        ArrayList<Byte> byteList = new ArrayList<Byte>();
        while(val != 0){
            byteList.add(srcByte[start+i]);
            val = srcByte[start+i];
            i++;
        }
        byte[] valAry = new byte[byteList.size()];
        for(int j=0;j<byteList.size();j++){
            valAry[j] = byteList.get(j);
        }
        try{
            return new String(valAry, "UTF-8");
        }catch(Exception e){
            System.out.println("encode error:"+e.toString());
            return "";
        }
    }

    /**
     * 读取C语言中的uleb类型
     * 目的是解决整型数值浪费问题
     * 长度不固定，在1~5个字节中浮动
     * @param srcByte
     * @param offset
     * @return
     */
    public static byte[] readUnsignedLeb128(byte[] srcByte, int offset){
        List<Byte> byteAryList = new ArrayList<Byte>();
        byte bytes = Utils.copyByte(srcByte, offset, 1)[0];
        byte highBit = (byte)(bytes & 0x80);
        byteAryList.add(bytes);
        offset ++;
        while(highBit != 0){
            bytes = Utils.copyByte(srcByte, offset, 1)[0];
            highBit = (byte)(bytes & 0x80);
            offset ++;
            byteAryList.add(bytes);
        }
        byte[] byteAry = new byte[byteAryList.size()];
        for(int j=0;j<byteAryList.size();j++){
            byteAry[j] = byteAryList.get(j);
        }
        return byteAry;
    }

    /**
     * 解码leb128数据
     * 每个字节去除最高位，然后进行拼接，重新构造一个int类型数值，从低位开始
     * @param byteAry
     * @return
     */
    public static int decodeUleb128(byte[] byteAry) {
        int index = 0, cur;
        int result = byteAry[index];
        index++;

        if(byteAry.length == 1){
            return result;
        }

        if(byteAry.length == 2){
            cur = byteAry[index];
            index++;
            result = (result & 0x7f) | ((cur & 0x7f) << 7);
            return result;
        }

        if(byteAry.length == 3){
            cur = byteAry[index];
            index++;
            result |= (cur & 0x7f) << 14;
            return result;
        }

        if(byteAry.length == 4){
            cur = byteAry[index];
            index++;
            result |= (cur & 0x7f) << 21;
            return result;
        }

        if(byteAry.length == 5){
            cur = byteAry[index];
            index++;
            result |= cur << 28;
            return result;
        }

        return result;

    }

    /**
     * 这里是解析一个字符串
     * 有两种方式
     * 1、第一个字节就是字符串的长度
     * 2、每个字符串的结束符是00
     * @param src
     * @param offset
     * @return
     */
    public static StringDataItem getString(byte[] src, int offset) {
        StringDataItem stringDataItem = new StringDataItem();
        //第一个字节为字符串长度
        byte size = src[offset];
        byte[] strByte = Utils.copyByte(src,offset + 1,size);
        stringDataItem.size = size;
        stringDataItem.srcBytes = strByte;
        try {
            stringDataItem.value = new String(strByte,"UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return stringDataItem;
    }

    public static String getStringByOff(List<StringDataItem> items,int offset) {
        if(items != null && offset < items.size()) {
            return items.get(offset).value;
        }
        return "";
    }

    public static String getProtoByOffset(List<ProtoIdsItem> items, int offset) {
        if(items != null && offset < items.size()) {
            return items.get(offset).getMethodStr();
        }
        return "";
    }

    public static int getTypeByOffset(List<TypeIdsItem> items,int offset) {
        if(items != null && offset < items.size()) {
            return items.get(offset).descriptor_idx;
        }
        return -1;
    }

    public static int readUnsignedLeb128(Buffer in) {
        int result = 0;
        int cur;
        int count = 0;

        do {
            byte b = in.readByte();//读取一个字节
            cur = b & 0xff; //该字节与0b11111111进行与操作,得到的应该还是其本身,这一步操作是否必要? 为了对齐8位？
            result |= (cur & 0x7f) << (count * 7); //该字节与0b0111111进行与操作,去除最高位,然后左移7*count位数,与result进行或运算连接,左移是因为是小端存储
            count++;
        } while (((cur & 0x80) == 0x80) && count < 5);//与0b10000000,最高位是1并且小于5个字节则一直循环

        //10000 0000 是非法的LEB128序列,0用00000000表示
        if ((cur & 0x80) == 0x80) {
            throw new RuntimeException("invalid LEB128 sequence");
        }

        return result;
    }

    public static String decode(Buffer in, char[] out) throws IOException {
        int s = 0;
        while (true) {
            char a = (char) (in.readByte() & 0xff);
            if (a == 0) {
                //字符串以\0结尾
                return new String(out, 0, s);
            }
            out[s] = a;
            if (a < '\u0080') {
                s++;
            } else if ((a & 0xe0) == 0xc0) {
                int b = in.readByte() & 0xff;
                if ((b & 0xC0) != 0x80) {
                    throw new UTFDataFormatException("bad second byte");
                }
                out[s++] = (char) (((a & 0x1F) << 6) | (b & 0x3F));
            } else if ((a & 0xf0) == 0xe0) {
                int b = in.readByte() & 0xff;
                int c = in.readByte() & 0xff;
                if (((b & 0xC0) != 0x80) || ((c & 0xC0) != 0x80)) {
                    throw new UTFDataFormatException("bad second or third byte");
                }
                out[s++] = (char) (((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F));
            } else {
                throw new UTFDataFormatException("bad byte");
            }
        }
    }

    public static void log(String msg) {
        Log.i("DexParse--->",msg);
    }
}
