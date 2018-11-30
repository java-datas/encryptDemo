public class KeyPairStr {

    private String publicKeyStr;
    private String privateKeyStr;

    public KeyPairStr() {
    }

    public KeyPairStr(String publicKeyStr, String privateKeyStr) {
        this.publicKeyStr = publicKeyStr;
        this.privateKeyStr = privateKeyStr;
    }

    public String getPublicKeyStr() {
        return publicKeyStr;
    }

    public void setPublicKeyStr(String publicKeyStr) {
        this.publicKeyStr = publicKeyStr;
    }

    public String getPrivateKeyStr() {
        return privateKeyStr;
    }

    public void setPrivateKeyStr(String privateKeyStr) {
        this.privateKeyStr = privateKeyStr;
    }
}
