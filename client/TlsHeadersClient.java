package mobile.computing.ws1819.client;

public class TlsHeadersClient {
	
	//as per rfc requirement
	public static final int HEADER_CLIENT_HELLO = 1;
	public static final int HEADER_SERVER_HELLO = 2;
	public static final int[] PROTOCOL_VERSION = { 0x03, 0x03 };
	public static final int[] CIPHER_SUITE = { 0x00, 0x04 };
	public static final int[] COMPRESSION_METHOD = { 0x01, 0x00 };
	public static final int HEADER_CERTIFICATE = 11;
	public static final int HEADER_CLIENT_KEY_EXCHANGE = 16;
	public static final int HEADER_SERVER_HELLO_DONE = 14;
	public static final int TLS_RSA_WITH_RC4_128_MD5 = 0x04;
	public static final byte[] PROTOCOL_VERSION_B = { 0x03, 0x03 };
	public static final byte CONTENTTYPE_CHANGE_CIPHER_SPEC = 20;
	public static final byte HEADER_FINISHED = 20;
	public static final int KEY_BLOCK_LENGTH = 104;
	public static int cipherSuite;
	public static byte[] masterSecret;	
	public static byte[] clientRandom;
}
