import org.junit.Before;
import org.junit.Test;

public class AESUtilTest {

    private String key,message;

    @Before
    public void  setup(){
        message = "这是一个测试字符串!";// 要加密的字符串;
        key = "1234567890123456";
    }



    /**
     * AES加解密数据
     *
     * @throws Exception
     */
    @Test
    public void aesEncrypt() throws Exception {
        String jiami = AESUtil.encrypt(key, message);
        System.out.println("加密前：" + message);
        System.out.println("密钥：" + key);
        System.out.println("加密后：" + jiami);
        String jiemi = AESUtil.decrypt(key, jiami);
        System.out.println("解密后：" + jiemi);
    }

}
