import org.apache.commons.codec.binary.Base64;
import org.junit.Before;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

public class RSAUtilTest {

    private String message;

    @Before
    public void setup() {
        message = "这是一个测试字符串!";// 要加密的字符串;
    }

    @Test
    public void go() throws Exception {

        System.out.println("准备用公钥加密的字符串为：" + message);
        Map<PublicKey, PrivateKey> keypair = RSAUtil.generateKeyPair();

        PublicKey publicKey = (PublicKey) keypair.keySet().toArray()[0];
        PrivateKey privateKey = keypair.get(publicKey);

        byte[] pk = publicKey.getEncoded();
        byte[] privk = privateKey.getEncoded();
        String publicKeyStr = Base64.encodeBase64String(pk);
        String privateKeyStr = Base64.encodeBase64String(privk);

        System.err.println("公钥:"+publicKeyStr);
        System.err.println("私钥:"+privateKeyStr);

        String data = RSAUtil.encryptToBase64(message.getBytes(), publicKeyStr);// 生成的密文
        System.out.println("用公钥加密后的结果为:" + data);
        byte[] inputdata = Base64.decodeBase64(data);//密文数据

        String target = RSAUtil.decryptToString(inputdata, privateKeyStr);// 解密密文
        System.out.println("用私钥解密后的字符串为：" + target);
    }

}
