package cn.eyecool.main.security;

import cn.eyecool.aes.AESUtil;
import cn.eyecool.des.TripleDesUtil;
import cn.eyecool.sm4.SM4Util;

/**
 * 
 * @ClassName: SecurityEntrance.java
 * @Description: 加解密算法入口类
 * @author lipeng
 * @Date 2020年11月20日 上午10:06:04 
 *
 */
public class SecurityEntrance {

    private static final String ALG_ERROR1 = " alg must be 1 or 2 or 3 ";
    private static final String LENGTH_ERROR = " length must be multiple of";
    private static final String KEY = "key";
    private static final String DATA = "data";
    private static SecurityEntrance securityEntrance;
    public String CODE = "UTF-8";
    // 私有化构造方法
    private SecurityEntrance() {}
    
    // 
    public static SecurityEntrance getInstance() {
        return getInstance(null);
    }
    /**
     * 双检锁单例
     * @param codeStyle 编码类型
     * @return
     */
    public static SecurityEntrance getInstance(String codeStyle) {
        if (securityEntrance == null) {
            synchronized (SecurityEntrance.class) {
                if (securityEntrance == null) {
                    securityEntrance = new SecurityEntrance();
                    if (codeStyle != null && codeStyle.trim().length() > 1) {
                        securityEntrance.CODE = codeStyle;
                    }
                }
            }
        }
        return securityEntrance;
    }
    /**
     * 对称加密
     * @param alg 1:AES 2:3DES 3:SM4
     * @param key 秘钥
     * @param plaintext 加密明文
     * @return 密文source
     * @throws Exception 
     */
    public String keyEncrypt(int alg, String key, String plaintext)
        throws Exception {
        if (alg != 1 && alg != 2 && alg != 3) {
            throw new Exception(ALG_ERROR1);
        }
        checkParam(KEY, key, 32);
        // SM4加密
        if (alg == 3) {
            return SM4Util.encodeSms4ToHex(plaintext, SecurityUtils.hexStringToBytes(key));
        }
        // DES加密
        if (alg == 2) {
            return TripleDesUtil.desEncrypt(key, plaintext);
        }
        // AES加密
        if (alg == 1) {
            return AESUtil.encryptAesToHex(plaintext,key);
        }
        return null;
    }
    
    /**
     * 对称解密
     * @param alg 算法标识  1:AES 2:3DES 3:SM4
     * @param key 密钥
     * @param cipherData 数据密文
     * @return 明文数据
     * @throws Exception 
     */
    public String keyDecrypt(int alg, String key, String cipherData) throws Exception {
        if (alg != 1 && alg != 2 && alg != 3) {
            throw new Exception(ALG_ERROR1);
        }
        checkParam(KEY, key, 32);
        checkParam(DATA,cipherData,32);
        // SM4解密
        if (alg == 3) {
            return SM4Util.decodeSms4HexToString(cipherData, SecurityUtils.hexStringToBytes(key));
        }
        // DES解密
        if (alg == 2) {
            return TripleDesUtil.desDecrypt(key, cipherData);
        }
        // AES解密
        if (alg == 1) {
            return AESUtil.decryptAes(key, cipherData);
        }
        return null;
    }
   
    /**
     * 非对称加密（公钥加密）
     * @param alg 算法标识 1=SM2
     * @param key 秘钥
     * @param cipherData 明文数据
     * @return
     */
    public static String publicEncrypt(int alg, String key, String cipherData) {
        if(alg == 1) {
        }
        return null;
        
    }
    
    /**
     * 生成秘钥
     * @param alg 算法标识  1:AES 2:3DES 3:SM4
     * @param keySize 秘钥长度,ASE{128、192、256},DES{112、168}
     * @return
     * @throws Exception 
     */
    public String GenerateSymmetricKey(int alg) throws Exception {
        if (alg != 1 && alg != 2 && alg != 3) {
            throw new Exception(ALG_ERROR1);
        }
        // SM4
        if(alg == 3) {
            return SM4Util.generateSM4Key();
        }
        // AES
        if(alg == 1) {
            return AESUtil.generateAesKey();
        }
        // 3DES
        if(alg == 2) {
            return TripleDesUtil.generateThreeDESKey();
        }
        return null;
    }
    
    private void checkParam(String name, String data, int length)
        throws Exception {
        if (!SecurityUtils.isEmpty(data) || (length != 0 && data.length() % length != 0)) {
            throw new Exception((new StringBuilder(name)).append(LENGTH_ERROR).append(length).toString());
        }
    }
    
}
