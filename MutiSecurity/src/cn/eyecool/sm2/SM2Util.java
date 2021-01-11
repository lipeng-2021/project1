package cn.eyecool.sm2;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import cn.eyecool.main.security.SecurityEntrance;
import cn.eyecool.main.security.SecurityUtils;


public class SM2Util {

    private static SM2Util sm2Util;

    private byte[] pubKey;
    private byte[] priKey;
    
    private SM2Util() {}
    
  //获取公钥
    public byte[] getPubKey() {
        return pubKey;
    }
    //获取私钥
    public byte[] getPriKey() {
        return priKey;
    }
    public static SM2Util getInstance() {
        if (sm2Util == null) {
            synchronized (SM2Util.class) {
                if (sm2Util == null) {
                    sm2Util = new SM2Util();
                }
            }
        }
        return sm2Util;
    }
    
    /**
     * 获得公私钥对,[0]=公钥，[1]=私钥
     * @return 
     */
    public String[] generateKeyPair() {
        SM2 sm2 = SM2.Instance(); //生成SM2实例
        AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair(); //生成公私密钥对
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate(); //从密钥对中提取私钥参数
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic(); //从密钥对中提取公钥参数
        BigInteger privateKey = ecpriv.getD(); //私钥是个大整数
        ECPoint publicKey = ecpub.getQ(); //公钥是个点
        pubKey = publicKey.getEncoded();  //将椭圆曲线点转化为字节数组
        priKey = privateKey.toByteArray();  //将大整数转化为字节数组
        String key1 = SecurityUtils.bytesToHexString(pubKey);
        String key2 = SecurityUtils.bytesToHexString(priKey);
        return new String[] {key1, key2};
    }
    
    /**
     * 数据加密
     * @param publicKey 公钥
     * @param data 明文数据
     * @return
     * @throws IOException
     */
    
    public static String encrypt(byte[] publicKey, String dataStr)
        throws IOException {
        // 明文直接转byte
        byte[] data = dataStr.getBytes();
        byte source[] = new byte[data.length];
        System.arraycopy(data, 0, source, 0, data.length);
        Cipher cipher = new Cipher();
        SM2 sm2 = SM2.Instance();
        ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);
        ECPoint c1 = cipher.Init_enc(sm2, userKey);
        cipher.Encrypt(source);
        byte c3[] = new byte[32];
        cipher.Dofinal(c3);
        return (new StringBuilder(String.valueOf(SecurityUtils.bytesToHexString(c1.getEncoded()))))
            .append(SecurityUtils.bytesToHexString(source))
            .append(SecurityUtils.bytesToHexString(c3))
            .toString();
    }
    
    /**
     * 数据解密
     * @param privateKey 公钥
     * @param encryptedData
     * @return
     * @throws IOException
     */
    public static String decrypt(byte[] privateKey, String encryptedData) throws IOException {
        //加密字节数组转换为十六进制的字符串 长度变为encryptedData.length * 2
        String data = encryptedData;
        byte[] c1Bytes = SecurityUtils.hexStringToBytes(data.substring(0,130));
        int c2Len = SecurityUtils.hexStringToBytes(data).length - 97;
        byte c2[] = SecurityUtils.hexStringToBytes(data.substring(130, 130 + 2 * c2Len));
        byte c3[] = SecurityUtils.hexStringToBytes(data.substring(130 + 2 * c2Len, 194 + 2 * c2Len));
        
        SM2 sm2 = SM2.Instance();
        BigInteger userD = new BigInteger(1, privateKey);

        //通过C1实体字节来生成ECPoint
        ECPoint c1 = sm2.ecc_curve.decodePoint(c1Bytes);
        Cipher cipher = new Cipher();
        cipher.Init_dec(userD, c1);
        cipher.Decrypt(c2);
        cipher.Dofinal(c3);

        //返回解密结果
        return new String(c2,SecurityEntrance.getInstance().CODE);
    }
}
