import org.junit.Before;
import org.junit.Test;

public class DESUtilTest {


    private String message, desKey;

    @Before
    public void setup() {
        message = "这是一个测试字符串!";// 要加密的字符串;
        desKey = "1234567890123";
    }

    /**
     * DES 加密和解密数据
     * @throws Exception
     */
    @Test
    public void desEncrypt() throws Exception {
        String str = DESUtil.encrypt(desKey, message);
        System.out.println("加密前：" + message);
        System.out.println("密钥：" + desKey);
        System.out.println("加密后：" + str);
        String jiemi = DESUtil.decrypt(desKey, str);
        System.out.println("解密后：" + jiemi);
    }


}
