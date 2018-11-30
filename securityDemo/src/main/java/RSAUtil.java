import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA 1024位加密算法
 */
public class RSAUtil {
    /**
     * 指定加密算法为RSA
     */
    private static final String ALGORITHM = "RSA";
    /**
     * 密钥长度，用来初始化
     */
    private static final int KEYSIZE = 1024;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * 生成密钥对，返回对应的公钥和私钥
     *
     * @return
     * @throws Exception
     */
    public static Map<String, String> generateKeyPairStr() throws Exception {

        Map<PublicKey, PrivateKey> keypair = generateKeyPair();
        PublicKey publicKey = (PublicKey) keypair.keySet().toArray()[0];
        PrivateKey privateKey = keypair.get(publicKey);

        byte[] pk = publicKey.getEncoded();
        byte[] privk = privateKey.getEncoded();
        String strpk = Base64.encodeBase64String(pk);
        String strprivk = Base64.encodeBase64String(privk);
        Map<String, String> keypairStr = new HashMap<>();
        keypairStr.put(strpk, strprivk);
        return keypairStr;
    }

    public static KeyPairStr generateKeyPairStrToBean() throws Exception {
        Map<PublicKey, PrivateKey> keypair = generateKeyPair();
        PublicKey publicKey = (PublicKey) keypair.keySet().toArray()[0];
        PrivateKey privateKey = keypair.get(publicKey);

        byte[] pk = publicKey.getEncoded();
        byte[] privk = privateKey.getEncoded();
        String strpk = Base64.encodeBase64String(pk);
        String strprivk = Base64.encodeBase64String(privk);

        return new KeyPairStr(strpk, strprivk);
    }

    /**
     * 生成密钥对
     *
     * @throws Exception
     */
    public static Map<PublicKey, PrivateKey> generateKeyPair() throws Exception {

        Map<PublicKey, PrivateKey> keypair = new HashMap<>();
        /** 为RSA算法创建一个KeyPairGenerator对象 */

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, "BC");
        /** 利用上面的随机数据源初始化这个KeyPairGenerator对象 */

        keyPairGenerator.initialize(KEYSIZE);

        /** 生成密匙对 */
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        /** 得到公钥 */
        PublicKey publicKey = keyPair.getPublic();
        /** 得到私钥 */
        PrivateKey privateKey = keyPair.getPrivate();
        keypair.put(publicKey, privateKey);
        return keypair;
    }

    /**
     * 公钥加密
     *
     * @param source
     * @param base64_publicKey
     * @return base64编码的密文
     * @throws Exception
     */
    public static String encryptToBase64(byte[] source, String base64_publicKey) throws Exception {
        X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(Base64.decodeBase64(base64_publicKey));
        KeyFactory keyf = KeyFactory.getInstance(ALGORITHM, "BC");
        PublicKey pubkey2 = keyf.generatePublic(pubX509);
        return encryptToBase64(source, pubkey2);
    }

    /**
     * 公钥加密
     *
     * @param source
     * @param base64_publicKey
     * @return 密文数组
     * @throws Exception
     */
    public static byte[] encrypt(byte[] source, String base64_publicKey) throws Exception {
        X509EncodedKeySpec pubX509 = new X509EncodedKeySpec(Base64.decodeBase64(base64_publicKey));
        KeyFactory keyf = KeyFactory.getInstance(ALGORITHM, "BC");
        PublicKey pubkey2 = keyf.generatePublic(pubX509);
        return encrypt(source, pubkey2);
    }

    /**
     * 加密方法:公钥加密
     *
     * @param source 源数据
     * @return base64编码的密文
     * @throws Exception
     */
    public static String encryptToBase64(byte[] source, Key publicKey) throws Exception {
        byte[] b1 = encrypt(source, publicKey);
        return Base64.encodeBase64String(b1);
    }

    /**
     * 加密方法:公钥加密
     *
     * @param source 源数据
     * @return 密文数组
     * @throws Exception
     */
    public static byte[] encrypt(byte[] source, Key publicKey) throws Exception {
        /** 得到Cipher对象来实现对源数据的RSA加密 */
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        /** 执行加密操作 */
        byte[] b1 = cipher.doFinal(source);
        return b1;
    }

    /**
     * 私钥解密
     *
     * @param data
     * @param base64_privateKey
     * @return 明文数组
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, String base64_privateKey) throws Exception {
        PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(base64_privateKey));
        KeyFactory keyf = KeyFactory.getInstance(ALGORITHM, "BC");
        PrivateKey privateKey = keyf.generatePrivate(priPKCS8);
        return decrypt(data, privateKey);
    }

    /**
     * 私钥解密
     *
     * @param data
     * @param base64_privateKey
     * @return 明文
     * @throws Exception
     */
    public static String decryptToString(byte[] data, String base64_privateKey) throws Exception {

        PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(base64_privateKey));
        KeyFactory keyf = KeyFactory.getInstance(ALGORITHM, "BC");
        PrivateKey privkey = keyf.generatePrivate(priPKCS8);
        return decryptToString(data, privkey);
    }

    /**
     * 私钥解密
     *
     * @param data 密文
     * @return 明文
     * @throws Exception
     */
    public static String decryptToString(byte[] data, Key privateKey) throws Exception {

        return new String(decrypt(data, privateKey));
    }

    /**
     * 私钥解密
     *
     * @param data 密文
     * @return 明文数组
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, Key privateKey) throws Exception {

        /** 得到Cipher对象对已用公钥加密的数据进行RSA解密 */
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        /** 执行解密操作 */
        byte[] b = cipher.doFinal(data);
        return b;
    }

}
