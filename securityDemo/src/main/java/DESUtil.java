import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;


public class DESUtil {


    private static  final  String  VAL = "01235678"; //8位


    /**
     *  加密
     * @param strKey 加密的key
     * @param data
     * @return
     */
    public static byte[] encrypt(String strKey,byte[] data) throws Exception {
        //建立分组加密方式 ： ps:对称加密分为分组加密 和序列加密
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(VAL.getBytes("UTF-8"));
        SecretKey secretKey = getkey(strKey);
        //Cipher.ENCRYPT_MODE 常数用于将密码初始化为加密模式。
        cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivParameterSpec);//使用密钥和一组算法参数初始化此密码。
        return   cipher.doFinal(data);//完成多部分加密或解密操作，这取决于该密码如何初始化
    }

    /**
     * 解密
     * @param strKey
     * @param data
     * @return
     * @throws Exception
     */
    public static  byte[] decrypt(String strKey,byte[] data) throws Exception{
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(VAL.getBytes("UTF-8"));
        SecretKey secretKey = getkey(strKey);
        cipher.init(Cipher.DECRYPT_MODE,secretKey,ivParameterSpec);//
        return   cipher.doFinal(data);
    }


    /**
     * 获取一个对称密健
     * @param strKey
     * @return
     * @throws Exception
     */
    private static SecretKey getkey(String strKey)throws Exception{
        // 创建使用前8个字节中一个DESKeySpec对象， strKey作为DES密钥的密钥材料。
        DESKeySpec desKeySpec = new DESKeySpec(strKey.getBytes("UTF-8"));
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
        //指定初始化对称IV向量
        return secretKey;
    }


    public static  String encrypt(String strKey,String data)throws Exception{
        byte[] encryptedData = encrypt(strKey, data
                .getBytes("UTF-8"));
        return Base64.encodeBase64String(encryptedData);
    }


    public static  String decrypt(String strKey,String data)throws Exception{
        byte[] encrypted = Base64.decodeBase64(data);
        byte[] encryptedData = decrypt(strKey, encrypted);
        return new String(encryptedData,"UTF-8");
    }






}
