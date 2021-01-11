package cn.eyecool.aes;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import cn.eyecool.main.security.SecurityEntrance;
import cn.eyecool.main.security.SecurityUtils;

/**
 * 
 * @ClassName: AESUtil.java
 * @Description: AES/ECB/NoPadding 加解密类
 * @author lipeng
 * @Date 2020年11月20日 下午2:24:41 
 *
 */
public class AESUtil {
    
    private static final String CIPHER_TYPE = "AES/ECB/NoPadding";
    
    private static final String AES = "AES";
    
    private static final String SHA1PRNG = "SHA1PRNG";
    
    /**
     * 加密为hexString密文
     * @param aesKey 秘钥
     * @param plainData 明文
     * @return 密文
     * @throws Exception
     */
    public static String encryptAesToHex(String plainData, String aesKey)
        throws Exception {
        // 长度补足为16的倍数
        byte dataBt[] = SecurityUtils.bytePadding(plainData.getBytes(SecurityEntrance.getInstance().CODE), 16);
        // 字符串转字节数组
        byte aesKeyBt[] = SecurityUtils.hexStringToBytes(aesKey);
        // 基于JDk实现的AES加密
        // 根据字节数组生成AES密钥
        SecretKeySpec key = new SecretKeySpec(aesKeyBt, AES);
        // 创建密码器，AES/ECB/NoPadding 加密
        Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
        // 设置加密key
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte encryptedData[] = cipher.doFinal(dataBt);
        
        return SecurityUtils.bytesToHexString(encryptedData);
    }
    
    /**
     * 解密
     * @param aesKey
     * @param encData
     * @return
     * @throws Exception
     */
    public static String decryptAes(String aesKey, String encData)
        throws Exception {
        // 字符串转字节数组
        byte aesKeyBt[] = SecurityUtils.hexStringToBytes(aesKey);
        byte dataBt[] = SecurityUtils.hexStringToBytes(encData);
        // 根据字节数组生成AES密钥
        SecretKeySpec key = new SecretKeySpec(aesKeyBt, AES);
        // 创建密码器，AES/ECB/NoPadding 加密
        Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
        // 设置加密key
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte encryptedData[] = cipher.doFinal(dataBt);
        
        return new String(encryptedData).trim();
    }
    
    /**
     * 根据秘钥长度生成key
     * @param keySize 秘钥长度
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String generateAesKey()
        throws NoSuchAlgorithmException {
        // 秘钥生成器
        KeyGenerator kg = KeyGenerator.getInstance(AES);
        kg.init(128);
        SecretKey sk = kg.generateKey();
        byte skBt[] = sk.getEncoded();
        String skStr = SecurityUtils.bytesToHexString(skBt);
        return skStr;
    }

    /**
     * 根据传入秘钥明文生成密文
     * @param keySize
     * @param passWd
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String generateAesKey(int keySize, String passWd)
        throws NoSuchAlgorithmException {
        // 秘钥生成器
        KeyGenerator kg = KeyGenerator.getInstance(AES);
        SecureRandom random = SecureRandom.getInstance(SHA1PRNG);
        random.setSeed(passWd.getBytes());
        kg.init(keySize, random);
        SecretKey sk = kg.generateKey();
        byte skBt[] = sk.getEncoded();
        String skStr = SecurityUtils.bytesToHexString(skBt);
        return skStr;
    }
}
