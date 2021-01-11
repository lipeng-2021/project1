package cn.eyecool.des;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import cn.eyecool.main.security.SecurityEntrance;
import cn.eyecool.main.security.SecurityUtils;

/**
 * 三重数据加密算法
 * @ClassName: DesUtil.java
 * @Description: TODO
 * @author lipeng
 * @Date 2020年11月23日 下午2:26:14 
 *
 */
public class TripleDesUtil {
    
    private static final String CIPHER_TYPE = "DESede/ECB/NoPadding";
    private static final String DESEDE = "DESede";
    
    /**
     * des加密
     * @param key 秘钥
     * @param data 数据
     * @return
     * @throws Exception
     */
    public static String desEncrypt(String keyStr, String dataStr)
        throws Exception {
        byte[] key = SecurityUtils.hexStringToBytes(keyStr);
        byte[] data = SecurityUtils.bytePadding(dataStr.getBytes(SecurityEntrance.getInstance().CODE), 8);
        byte k[] = new byte[24];
        if (key.length == 16) {
            System.arraycopy(key, 0, k, 0, key.length);
            System.arraycopy(key, 0, k, 16, 8);
        } else {
            System.arraycopy(key, 0, k, 0, 24);
        }
        // JDK加解密
        java.security.spec.KeySpec ks = new DESedeKeySpec(k);
        SecretKeyFactory kf = SecretKeyFactory.getInstance(DESEDE);
        javax.crypto.SecretKey ky = kf.generateSecret(ks);
        Cipher c = Cipher.getInstance(CIPHER_TYPE);
        c.init(1, ky);
        byte b[] = c.doFinal(data);
        return SecurityUtils.bytesToHexString(b);
    }
    
    /**
     * 解密
     * @param key
     * @param data
     * @return
     * @throws Exception
     */
    public static String desDecrypt(String keyStr, String data)
        throws Exception {
        byte[] key = SecurityUtils.hexStringToBytes(keyStr);
        byte k[] = new byte[24];
        if (key.length == 16) {
            System.arraycopy(key, 0, k, 0, key.length);
            System.arraycopy(key, 0, k, 16, 8);
        } else {
            System.arraycopy(key, 0, k, 0, 24);
        }
        java.security.spec.KeySpec ks = new DESedeKeySpec(k);
        SecretKeyFactory kf = SecretKeyFactory.getInstance(DESEDE);
        javax.crypto.SecretKey ky = kf.generateSecret(ks);
        Cipher c = Cipher.getInstance(CIPHER_TYPE);
        c.init(2, ky);
        byte[] desRes = c.doFinal(SecurityUtils.hexStringToBytes(data));
        return new String(desRes, SecurityEntrance.getInstance().CODE).trim();
    }
    
    /**
     * 获取秘钥,16进制字符串
     * @param keySize
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String generateThreeDESKey()
        throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance(DESEDE);
        kg.init(112);
        SecretKey sk = kg.generateKey();
        String keyRes = SecurityUtils.bytesToHexString(sk.getEncoded());
        return keyRes.substring(6, 38);
    }
}
