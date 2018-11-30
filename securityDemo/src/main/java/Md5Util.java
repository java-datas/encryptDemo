import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Md5Util {


    public static MessageDigest md5 = null;


    /** 第一种写法
     * md5 加密
     *
     * @param str
     * @return
     * @throws UnsupportedEncodingException
     */
    public static String md5Encode(String str) throws UnsupportedEncodingException {
        if (str == null) {
            return null;
        }
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace();
            return "";
        }
        byte[] byteArray = str.getBytes("UTF-8");
        byte[] md5Bytes = md5.digest(byteArray);
        StringBuffer hexValue = new StringBuffer();
        for (int i = 0; i < md5Bytes.length; i++) {
            int val = (int) md5Bytes[i] & 0xff;
            if (val < 16) {
                hexValue.append("0");
            }
            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();
    }

    /** 第二种写法
     * md5 加密
     *
     * @param str
     * @return
     * @throws UnsupportedEncodingException
     */

    public static String md5Encode1(String str) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest m = MessageDigest.getInstance("MD5");
        byte[] bytes = str.getBytes("UTF-8");
        //计算md5函数
        m.update(bytes);
        // digest()最后确定返回md5 hash值，返回值为8为字符串。因为md5 hash值是16位的hex值，实际上就是8位的字符
        // BigInteger函数则将8位的字符串转换成16位hex值，用字符串来表示；得到字符串形式的hash值
        return new BigInteger(1,m.digest()).toString(16);
    }


}
