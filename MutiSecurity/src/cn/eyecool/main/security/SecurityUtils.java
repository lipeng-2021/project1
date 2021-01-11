package cn.eyecool.main.security;

import java.math.BigInteger;

/**
 * 
 * @ClassName: SecurityUtils.java
 * @Description: 加解密工具类
 * @author lipeng
 * @Date 2020年11月20日 上午10:38:48 
 *
 */
public class SecurityUtils {

    public static final char ADD_CHAR = '\0';
    
    private static final String EMPTY = "";
    

    /**
     * 字节数组转16进制字符串，长度*2
     *
     * @param src 字节数组
     * @return String
     */
    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder();
        if (src == null || src.length <= 0) {
            return null;
        }
        for (byte aSrc : src) {
            int v = aSrc & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv.toUpperCase());
        }
        return stringBuilder.toString();
    }
    
    /**
     * 16进制字符串转字节数组，长度缩减一半
     *
     * @param hexString the hex string
     * @return byte[]
     */
    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.length() <= 0) {
            return null;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte)(charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }
    
    /**
     * 判断字符串是否为空
     * @param obj
     * @return
     */
    public static boolean isEmpty(String obj) {
        if(obj == null || EMPTY.equals(obj)) {
            return false;
        }
        return true;
    }
    /**
     * Convert char to byte
     *
     * @param c char
     * @return byte
     */
    private static byte charToByte(char c) {
        return (byte)"0123456789ABCDEF".indexOf(c);
    }

    /**
     * 数组长度补位
     * @param src 原
     * @param length 长度倍
     * @return 结果
     */
    public static byte[] bytePadding(byte[] src, int length) {
        int addLength = length - src.length % length;
        byte[] resByte = new byte[src.length + addLength];
        System.arraycopy(src, 0, resByte, 0, src.length);
        for (int i = 0; i < addLength; i++) {
            resByte[src.length + i] = (byte)addLength;
        }
        
        return resByte;
    }
    
    /**
     * 大数字转换字节流（字节数组）型数据
     *
     * @param n
     * @return
     */
    public static byte[] byteConvert32Bytes(BigInteger n) {
        byte tmpd[] = (byte[]) null;
        if (n == null) {
            return null;
        }

        if (n.toByteArray().length == 33) {
            tmpd = new byte[32];
            System.arraycopy(n.toByteArray(), 1, tmpd, 0, 32);
        } else if (n.toByteArray().length == 32) {
            tmpd = n.toByteArray();
        } else {
            tmpd = new byte[32];
            for (int i = 0; i < 32 - n.toByteArray().length; i++) {
                tmpd[i] = 0;
            }
            System.arraycopy(n.toByteArray(), 0, tmpd, 32 - n.toByteArray().length, n.toByteArray().length);
        }
        return tmpd;
    }
    
}
