import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {

    private static final String VAL = "0123456789654321"; //必须16位


    /**
     * AES加密
     *
     * @param strKey 为16 24 32位 =>对应的加密位数为128 192 256 一个字节8位
     * @param data   明文数据
     * @return
     * @throws Exception
     */
    public static byte[] enrypt(String strKey, byte[] data) throws Exception {
        IvParameterSpec ivParameterSpec = new IvParameterSpec(VAL.getBytes("UTF-8"));
        SecretKeySpec keySpec = new SecretKeySpec(strKey.getBytes("UTF-8"), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParameterSpec);
        byte[] encryptData = cipher.doFinal(data);
        return encryptData;
    }

    /**
     * AES 解密
     *
     * @param strKey
     * @param encrypted 密文数据
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(String strKey, byte[] encrypted)
            throws Exception {
        IvParameterSpec zeroIv = new IvParameterSpec(VAL.getBytes("UTF-8"));
        SecretKeySpec key = new SecretKeySpec(strKey.getBytes("UTF-8"), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, zeroIv);
        byte[] decryptedData = cipher.doFinal(encrypted);
        return decryptedData;
    }


    //AES加密
    public static String encrypt(String key, String data) throws Exception {
        byte[] encryptData = enrypt(key, data.getBytes("UTF-8"));
        return Base64.encodeBase64String(encryptData);
    }

    //AES解密
    public static String decrypt(String key, String string_base64) throws Exception {
        byte[] encryptData = Base64.decodeBase64(string_base64);
        byte[] decryptData = decrypt(key, encryptData);
        return new String(decryptData, "UTF-8");
    }


}
