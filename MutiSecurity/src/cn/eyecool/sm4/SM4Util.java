package cn.eyecool.sm4;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SM3Digest;

import cn.eyecool.main.security.SecurityEntrance;
import cn.eyecool.main.security.SecurityUtils;

public class SM4Util {

    // 加密算法/分组加密模式/分组填充方式
    // PKCS5Padding-以8个字节为一组进行分组加密
    // 定义分组加密模式使用：PKCS5Padding
    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";
    
    public static final String ALGORITHM_NAME = "SM4";
    
    /**
     * 字符串加密
     *
     * @param plaintext 明文
     * @param key       秘钥
     * @return 加密后的明文字符串
     * @throws UnsupportedEncodingException 
     * @Author lipeng
     */
    public static String encodeSms4ToHex(String plaintext, byte[] key)
        throws UnsupportedEncodingException {
        // 长度补足为16的倍数
        byte[] dateBt = SecurityUtils.bytePadding(plaintext.getBytes(SecurityEntrance.getInstance().CODE), 16);
        return SecurityUtils.bytesToHexString(encodeSms4(dateBt, key));
    }
    
    /**
     * 字符串形式的密文解密成明文
     *
     * @param enHex 密文
     * @param key   秘钥
     * @return 解密后的明文
     * @Author lipeng
     */
    public static String decodeSms4HexToString(String enHex, byte[] key) {
        byte[] plaintext = decodeSms4(SecurityUtils.hexStringToBytes(enHex),key);
        return new String(plaintext).trim();
    }
    
    /**
     * SMS4加密，加密字符数组
     *
     * @param plaintext 字节数组形式的明文
     * @param key       秘钥
     * @return 明文加密后的字接数组
     */
    private static byte[] encodeSms4(byte[] plaintext, byte[] key) {
        byte[] ciphering = new byte[plaintext.length];
        int k = 0;
        int plainLen = plaintext.length;
        while (k + SM4.BLOCK <= plainLen) {
            byte[] cellPlain = new byte[16];
            System.arraycopy(plaintext, k, cellPlain, 0, 16);
            byte[] cellCipher = encode16(cellPlain, key);
            System.arraycopy(cellCipher, 0, ciphering, k, cellCipher.length);
            k += 16;
        }
        return ciphering;
    }
    
    /**
     * 只加密16位明文
     *
     * @param plaintext 明文字节数组
     * @param key       秘钥
     * @return 加密后的字节数组
     */
    private static byte[] encode16(byte[] plaintext, byte[] key) {
        byte[] cipher = new byte[16];
        SM4 sm4 = new SM4();
        //调用加密方法
        return sm4.sms4(plaintext, 16, key, cipher, SM4.ENCRYPT);
    }
    
    /**
     * 只解密16位密文
     *
     * @param ciphering 需解密的密文
     * @param key 秘钥
     * @return 解密后的明文字节
     */
    private static byte[] decode16(byte[] ciphering, byte[] key) {
        byte[] plain = new byte[16];
        SM4 sm4 = new SM4();
        sm4.sms4(ciphering, 16, key, plain, SM4.DECRYPT);
        return plain;
    }
    
   /**
    * 不限明文长度的SMS4解密
    *
    * @param ciphering 需要解密的字节数组
    * @param key 秘钥
    * @return 解密后的字节数组
    */
   private static byte[] decodeSms4(byte[] ciphering, byte[] key) {
       byte[] plaintext = new byte[ciphering.length];
       int k = 0;
       int cipherLen = ciphering.length;
       while (k + SM4.BLOCK <= cipherLen) {
           byte[] cellCipher = new byte[16];
           System.arraycopy(ciphering, k, cellCipher, 0, 16);
           byte[] cellPlain = decode16(cellCipher, key);
           System.arraycopy(cellPlain, 0, plaintext, k, cellPlain.length);
           k += SM4.BLOCK;
       }

       return plaintext;
   }
   
   /**
    * 生成32位SM4秘钥
    * @return 秘钥
    */
    public static String generateSM4Key() {
        // 加密随机对象
        SecureRandom sRandom = new SecureRandom();
        // 随机数字符串
        String sRdInt = (new StringBuilder(String.valueOf(sRandom.nextLong()))).toString();
        // 使用sm3对随机数加密
        byte sm3Out[] = new byte[32];
        SM3Digest sm3D = new SM3Digest();
        sm3D.update(sRdInt.getBytes(), 0, sRdInt.getBytes().length);
        sm3D.doFinal(sm3Out, 0);
        // 转成16进制字符串
        String sm3OutStr = SecurityUtils.bytesToHexString(sm3Out);
        // 从第十位开始取32位
        String sm4Key = sm3OutStr.substring(10, 42);
        return sm4Key;
    }
   
    /**
     * 对明文秘钥加密
     * @param passWd
     * @return
     */
    public static String generateSM4Key(String passWd) {
        SecureRandom sRandom = new SecureRandom(passWd.getBytes());
        String sRdInt = (new StringBuilder(String.valueOf(sRandom.nextLong()))).toString();
        byte sm3Out[] = new byte[32];
        SM3Digest sm3D = new SM3Digest();
        sm3D.update(sRdInt.getBytes(), 0, sRdInt.getBytes().length);
        sm3D.doFinal(sm3Out, 0);
        String sm3OutStr = SecurityUtils.bytesToHexString(sm3Out);
        // 倒数从十位开始取32位
        String sm4Key = sm3OutStr.substring(22, 54);
        return sm4Key;
    }
}
