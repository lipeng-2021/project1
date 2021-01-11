package test;

import java.io.IOException;

import cn.eyecool.main.security.SecurityEntrance;
import cn.eyecool.main.security.SecurityUtils;
import cn.eyecool.sm2.SM2Util;

public class MainTest {
    private static String key = "java1314java1314java1314java1314";
    
    private static String plainData = "this is a testjava1314java1314java1314java1314";
    
    public static void main(String[] args) {
        try {
            testSM4();
//            testAES();
//            testDes();
//            testSM2();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    private static void testSM4() throws Exception {
        key = SecurityEntrance.getInstance().GenerateSymmetricKey(3);
        String result1 = SecurityEntrance.getInstance().keyEncrypt(3, key, plainData);
        String result2 = SecurityEntrance.getInstance().keyDecrypt(3, key, result1);
        System.out.println(result1);
        System.out.println(result2);
    }
    
    private static void testAES() throws Exception {
        key = SecurityEntrance.getInstance().GenerateSymmetricKey(1);
        System.out.println("key = " + key);
        String result1 = SecurityEntrance.getInstance().keyEncrypt(1, key, plainData);
        System.out.println(result1);
        String result2 = SecurityEntrance.getInstance().keyDecrypt(1, key, result1);
        System.out.println(result2);
    }
    
    private static void testDes() throws Exception {
        key = SecurityEntrance.getInstance().GenerateSymmetricKey(2);
        System.out.println("key = " + key);
        String result1 = SecurityEntrance.getInstance().keyEncrypt(2, key, plainData);
        System.out.println(result1);
        String result2 = SecurityEntrance.getInstance().keyDecrypt(2, key, result1);
        System.out.println(result2);
    }
    
    private static void testSM2() throws IOException {
        SM2Util sm2 = SM2Util.getInstance();
        sm2.generateKeyPair();
        String result1 = SM2Util.encrypt(sm2.getPubKey(), plainData);
        System.out.println(result1);
        String result2 = SM2Util.decrypt(sm2.getPriKey(), result1);
        System.out.println(result2);
    }
}
