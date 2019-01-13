package mobile.computing.ws1819.client;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.core.MediaType;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;

import mobile.computing.ws1819.HMAC;
import mobile.computing.ws1819.TlsException;

public class RecordLayerClient {

	public static final byte ALERT_CLOSE_NOTIFY = 0;
	public static final byte ALERT_WARNING = 1;
	public static final byte ALERT_FATAL = 2;
	public static final byte ALERT_UNEXPECTED_MESSAGE = 10;
	public static final byte ALERT_HANDSHAKE_FAILURE = 40;
	public static final byte ALERT_UNSUPPORTED_CERTIFICATE = 43;
	public static final int CONTENTTYPE_CHANGE_CIPHER_SPEC = 20;
	public static final byte CONTENTTYPE_ALERT = 21;
	public static final byte CONTENTTYPE_HANDSHAKE = 22;
	public static final byte CONTENTTYPE_APPLICATION_DATA = 23;
	public static final int MAX_FRAGMENT_SIZE = 2047;
	private static boolean clientWriteCipherIsNull = true;
	private static long clientWriteSeqNum = 0;
	private static boolean serverWriteCipherIsNull = true;
	private long serverWriteSeqNum = 0;
	private static HMAC hmacClientWrite;
	private static HMAC hmacServerWrite;
	private static Cipher encryptCipher;
	private static Cipher decryptCipher;
	private static int macSize;
	private static int blockSize;
	private static byte[] readBuf = new byte[18442];

	/*
	 * To define types of Handshakes
	 */
	enum handshakeTypes {
		ClientHello, ClientKeyExchange, ChangeCipherSpec, SendFinished
	};

	/*
	 * Switch case to send the respective post requests based on handshakes
	 * 
	 * @param:String,HandshakeTypes
	 * 
	 * @return:void
	 */
	public void sendHandshakeMessage(String messageAsJSONstring, handshakeTypes type) {

		switch (type) {
		case ClientHello:
			Client create1 = Client.create();
			WebResource service1 = create1.resource("http://127.0.0.1:8080/api");

			@SuppressWarnings("unused")
			String response1 = service1.path("message/ClientHello").type(MediaType.APPLICATION_JSON).post(String.class,
					messageAsJSONstring);
			break;
		case ClientKeyExchange:
			Client create2 = Client.create();
			WebResource service2 = create2.resource("http://127.0.0.1:8080/api");

			@SuppressWarnings("unused")
			String response2 = service2.path("message/ClientKeyExchange").type(MediaType.APPLICATION_JSON)
					.post(String.class, messageAsJSONstring);
			break;
		case ChangeCipherSpec:
			Client create3 = Client.create();
			WebResource service3 = create3.resource("http://127.0.0.1:8080/api");

			@SuppressWarnings("unused")
			String response3 = service3.path("message/ChangeCipherSpec").type(MediaType.APPLICATION_JSON)
					.post(String.class, messageAsJSONstring);

			changeClientWriteState();
			break;
		case SendFinished:
			Client create4 = Client.create();
			WebResource service4 = create4.resource("http://127.0.0.1:8080/api");

			@SuppressWarnings("unused")
			String response4 = service4.path("message/SendFinished").type(MediaType.APPLICATION_JSON).post(String.class,
					messageAsJSONstring);
			break;
		default:
			break;

		}
	}

	/*
	 * Promote the pending write state to be the current state
	 */
	public void changeClientWriteState() {
		clientWriteCipherIsNull = !clientWriteCipherIsNull;
	}

	private byte[] getMAC(HMAC hmac, byte[] seqNum, byte type, byte[] message, int offset, int length) {

		byte[] input = new byte[13 + length];
		System.arraycopy(seqNum, 0, input, 0, 8);
		input[8] = type;
		System.arraycopy(TlsHeadersClient.PROTOCOL_VERSION_B, 0, input, 9, 2);
		input[11] = (byte) (length >> 8);
		input[12] = (byte) (length);
		System.arraycopy(message, offset, input, 13, length);

		return hmac.digest(input);
	}

	private static byte[] subByte(byte[] buf, int offset, int len) {
		byte[] result = new byte[len];
		System.arraycopy(buf, offset, result, 0, len);
		return result;
	}

	/*
	 * To read the encrypted Server Send Finished messaged sent by server.Performs
	 * decryption
	 * 
	 * @param:byte[]
	 * 
	 * @return:byte[]
	 */
	public byte[] readRecord(byte[] msg) throws TlsException {
		int recordLength = 0;

		byte[] decoded = msg;

		readBuf = decoded;

		byte[] fragment = new byte[decoded.length];

		// decrypt if serverWriteCipherIsNull is false
		if (!serverWriteCipherIsNull) {
			try {
				decryptCipher.update(readBuf, 0, decoded.length, fragment);
			} catch (Exception e) {
			}

			int fragmentLength = decoded.length - macSize;
			// subtract padding from fragmentLength
			if (blockSize > 0) {
				fragmentLength -= ((fragment[recordLength - 1] & 0xff) + 1);
			}

			byte[] seqNum = long2ByteArray(serverWriteSeqNum++);
			@SuppressWarnings("unused")
			byte[] mac = getMAC(hmacServerWrite, seqNum, readBuf[0], fragment, 0, decoded.length);

			// log("mac good!");
			byte[] fragmentNoMac = new byte[fragmentLength];
			System.arraycopy(fragment, 0, fragmentNoMac, 0, fragmentLength);
			fragment = fragmentNoMac;

		}

		return fragment;
	}

	/*
	 * Sets the key block for the pending state.
	 *
	 * @param keyBlock enough material to set all keys
	 */
	public void setKeyBlock(int cipherSuite, byte[] keyBlock) {
		try {
			// assume TLS_RSA_WITH_RC4_128_MD5
			macSize = 16;
			blockSize = 0;
			int keySize = 16;
			int ivSize = 0;
			String keyAlg = "RC4";
			String cipherAlg = "RC4";
			String macAlg = "MD5";

			byte[] clientWriteMACSecret = subByte(keyBlock, 0, macSize);
			byte[] serverWriteMACSecret = subByte(keyBlock, macSize, macSize);
			byte[] clientWriteKey = subByte(keyBlock, 2 * macSize, keySize);
			byte[] serverWriteKey = subByte(keyBlock, 2 * macSize + keySize, keySize);
			byte[] clientWriteIV = subByte(keyBlock, 2 * (macSize + keySize), ivSize);
			byte[] serverWriteIV = subByte(keyBlock, 2 * (macSize + keySize) + ivSize, ivSize);

			hmacClientWrite = new HMAC(MessageDigest.getInstance(macAlg), clientWriteMACSecret);
			hmacServerWrite = new HMAC(MessageDigest.getInstance(macAlg), serverWriteMACSecret);

			encryptCipher = Cipher.getInstance(cipherAlg);
			decryptCipher = Cipher.getInstance(cipherAlg);

			// no IV for RC4
			if (cipherSuite == TlsHeadersClient.TLS_RSA_WITH_RC4_128_MD5) {
				encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(clientWriteKey, keyAlg));
				decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(serverWriteKey, keyAlg));
			} else {
				encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(clientWriteKey, keyAlg),
						new IvParameterSpec(clientWriteIV));
				decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(serverWriteKey, keyAlg),
						new IvParameterSpec(serverWriteIV));
			}

		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
	}

	/*
	 * Converting long to Byte Array
	 * 
	 * @param: long
	 * 
	 * @return:byte[]
	 */
	private byte[] long2ByteArray(long l) {

		byte[] byteVal = new byte[8];
		byteVal[7] = (byte) (l);
		byteVal[6] = (byte) (l >> 8);
		byteVal[5] = (byte) (l >> 16);
		byteVal[4] = (byte) (l >> 24);
		byteVal[3] = (byte) (l >> 32);
		byteVal[2] = (byte) (l >> 40);
		byteVal[1] = (byte) (l >> 48);
		byteVal[0] = (byte) (l >> 56);
		return byteVal;
	}

	/*
	 * To perform encryption on the application data
	 * 
	 */
	public byte[] sendMessage(byte contentType, byte[] msg) throws TlsException {

		// the fragment of the message that gets written each time.
		byte[] fragment = null;

		int msgBytesSent = 0;
		int msgBytesToSend = 0;
		int msgBytesRemaining = msg.length;

		byte[] length = { 0, 0 };

		msgBytesToSend = msgBytesRemaining > MAX_FRAGMENT_SIZE ? MAX_FRAGMENT_SIZE : msgBytesRemaining;
		// encrypt if required
		if (!clientWriteCipherIsNull) {
			byte[] seqNum = long2ByteArray(clientWriteSeqNum++);
			byte[] mac = getMAC(hmacClientWrite, seqNum, contentType, msg, msgBytesSent, msgBytesToSend);
			int paddingLen = blockSize == 0 ? 0 : blockSize - ((msgBytesToSend + mac.length) % blockSize);
			byte[] messageMacPad = new byte[msgBytesToSend + mac.length + paddingLen];
			System.arraycopy(msg, msgBytesSent, messageMacPad, 0, msgBytesToSend);
			System.arraycopy(mac, 0, messageMacPad, msgBytesToSend, mac.length);
			// put padding
			for (int i = 0; i < paddingLen; i++) {
				messageMacPad[messageMacPad.length - 1 - i] = (byte) (paddingLen - 1);
			}
			try {

				encryptCipher.update(messageMacPad, 0, messageMacPad.length, messageMacPad);
			} catch (Exception e) {
				throw new TlsException("encrypt error: " + e.getMessage());
			}
			fragment = messageMacPad;

			if (contentType == RecordLayerClient.CONTENTTYPE_APPLICATION_DATA) {

				String encodedMessage = new String(Base64.getEncoder().encode(fragment));

				System.out.println("Encrypted: " + encodedMessage);
			}

		} else {
			fragment = new byte[msgBytesToSend];
			System.arraycopy(msg, msgBytesSent, fragment, 0, msgBytesToSend);

			if (contentType == RecordLayerClient.CONTENTTYPE_APPLICATION_DATA) {

				String message = new String(fragment);

				System.out.println("\nEncrypted: " + message);
			}

		}
		length[0] = (byte) (fragment.length >> 8);
		length[1] = (byte) fragment.length;

		msgBytesSent += msgBytesToSend;
		msgBytesRemaining -= msgBytesToSend;

		return fragment;

	}

	/*
	 * Promote the pending read state to be the current state
	 */
	public void changeServerWriteState() {
		serverWriteCipherIsNull = !serverWriteCipherIsNull;
	}

}
