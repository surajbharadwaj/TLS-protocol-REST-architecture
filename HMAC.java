package mobile.computing.ws1819;

import java.security.MessageDigest;

public class HMAC {

    private byte[] k_ipad = new byte[64];
    private byte[] k_opad = new byte[64];
    MessageDigest md = null;

    /**
     * Class constructor specifying the MessageDigest and secret to use
     * @param md        the MessageDigest (MD5 or SHA1).
     * @param secret    the secret to seed the md.
     */
    public HMAC(MessageDigest md, byte[] key) {
        setMD(md);
        setKey(key);
    }

    /** Set the MessageDigest for HMAC
     * @param md    the MessageDigest
     */
    public void setMD(MessageDigest md) {
        this.md = md;
    }

    /**
     * Set the secret key for HMAC
     * @param key   the key.
     */
     public void setKey(byte[] key) {
        int keyLength = 0;

        // get keyLength.
        if (key == null) {
            keyLength = 0;
        } else {
            keyLength = key.length;
        }

        // if the key is longer than 64 bytes then hash it.
        byte[] tempKey = keyLength > 64 ? md.digest(key) : key;

        // get m_k_ipad and m_k_opad
        for (int i = 0; i < keyLength; i++) {
            k_ipad[i] = (byte) (0x36 ^ tempKey[i]);
            k_opad[i] = (byte) (0x5C ^ tempKey[i]);
        }

        for (int i = keyLength; i < 64; i++) {
            k_ipad[i] = 0x36;
            k_opad[i] = 0x5C;
        }
    }

    /**
     * Digest the HMAC
     * @param input the byte array input
     * @return HMAC value
     */
    public byte[] digest(byte[] input) {

        md.reset();
        md.update(k_ipad);
        md.update(input);
        byte[] inner = md.digest();
        md.update(k_opad);
        md.update(inner);
        return md.digest();
    }

}
