import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class Md5Test {

    private String passwod, securty;

    @Before
    public void stup() {
        passwod = "23";
        securty = "sdhfkjhdfskhjkh";
    }


    @Test
    public void testMetmhod() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        String str = Md5Util.md5Encode(passwod);
        String str1 = Md5Util.md5Encode(securty);
        System.out.println(str);
        System.out.println(str1);
        System.out.println(Md5Util.md5Encode1(passwod));
    }


}
