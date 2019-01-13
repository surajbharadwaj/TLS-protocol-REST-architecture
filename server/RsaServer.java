package mobile.computing.ws1819.server;

import java.security.PrivateKey;
import javax.crypto.Cipher;
import java.security.spec.PKCS8EncodedKeySpec;
import mobile.computing.ws1819.FileLoad;
import java.security.KeyFactory;

public class RsaServer {

	private final static String PRIVATE_KEY = "/privatekey.pkcs8";
	private PrivateKey privateKey;
	public final int CIPHER_SUITE = 4;

    /*
     * class constructor
     */
	public RsaServer() throws Exception {
		this.privateKey = getPrivate(PRIVATE_KEY);
	}

	/*
	 * To perform decryption
	 * @param:byte array
	 * @return:byte array
	 */
	public byte[] decrypt(byte[] inputData) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.PRIVATE_KEY, this.privateKey);

		byte[] decryptedBytes = cipher.doFinal(inputData);

		return decryptedBytes;
	}

	/*
	 * decode the pkcs8 encoded private key
	 * @param:String
	 * @return:Privatekey
	 */
	private PrivateKey getPrivate(String filename) throws Exception {
		byte[] keyBytes = FileLoad.loadFileAsBytesArray(filename);
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

}