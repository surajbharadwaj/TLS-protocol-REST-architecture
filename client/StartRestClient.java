package mobile.computing.ws1819.client;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Base64;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import javax.ws.rs.core.MediaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.container.httpserver.HttpServerFactory;
import com.sun.net.httpserver.HttpServer;
import mobile.computing.ws1819.client.TlsHeadersClient;
import mobile.computing.ws1819.server.TlsHeadersServer;
import mobile.computing.ws1819.Tls;
import mobile.computing.ws1819.TlsException;
import mobile.computing.ws1819.ApplicationData;
import mobile.computing.ws1819.ChangeCipherSpec;
import mobile.computing.ws1819.ClientKeyEXchange;
import mobile.computing.ws1819.PRF;
import mobile.computing.ws1819.SendFinished;

public class StartRestClient {
	public static MessageDigest md5;
	public static MessageDigest sha;
	public static MessageDigest tempMD;
	public static ByteArrayOutputStream baos;
	public static RsaClient rsa;
	public static PRF prf;
	public static RecordLayerClient recordLayer;
	public static Random randomGenerator;
	public static final int KEY_BLOCK_LENGTH = 104;
	private static byte[] clientRandom;
	public static byte[] masterSecret;

	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, CloneNotSupportedException {
		baos = new ByteArrayOutputStream();
		recordLayer = new RecordLayerClient();
		md5 = MessageDigest.getInstance("MD5");
		sha = MessageDigest.getInstance("SHA");
		prf = new PRF();
		rsa = new RsaClient();
		randomGenerator = new Random();
		md5.reset();
		sha.reset();

		HttpServer server = HttpServerFactory.create("http://127.0.0.1:8089/api");
		server.start();

		System.out.println("Handshake Process Started..");
        
		doPostRequestClientHello(); 

		doPostSendClientKeyExchange();

		doPostsendChangeCipherSpec();

		doPostsendFinished();

		System.out.println("Handshake Process Done!");

		while (true) {
			BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

			System.out.print("\nType message: ");

			String input = null;

			input = console.readLine();
			byte[] msg = input.getBytes();
			byte[] md5encoded = recordLayer.sendMessage(RecordLayerClient.CONTENTTYPE_APPLICATION_DATA, msg);
			String encoded = new String(Base64.getEncoder().encode(md5encoded));

			ApplicationData sendData = ApplicationData.data("Application Data", encoded);

			ObjectMapper mapperData = new ObjectMapper();
			String messageAsJSONstring = mapperData.writeValueAsString(sendData);

			Client create = Client.create();
			WebResource service = create.resource("http://127.0.0.1:8080/api");

			@SuppressWarnings("unused")
			String response = service.path("message/ApplicationData").type(MediaType.APPLICATION_JSON)
					.post(String.class, messageAsJSONstring);

		}

	}

	/*
	 * post request to send client hello message to the server
	 * preparing the contents to be sent through the record layer 
	 */
	private static void doPostRequestClientHello() throws IOException {

		clientRandom = getRandom();
		byte[] header = { TlsHeadersClient.HEADER_CLIENT_HELLO, 0x00, 0x00, 0x00 };

		baos.reset();
		baos.write(header);
		baos.write(TlsHeadersClient.PROTOCOL_VERSION_B);
		baos.write(clientRandom);
		baos.write(0);
		baos.write(TlsHeadersClient.CIPHER_SUITE[0]);
		baos.write(TlsHeadersClient.CIPHER_SUITE[1]);
		baos.write(TlsHeadersClient.COMPRESSION_METHOD[0]);
		baos.write(TlsHeadersClient.COMPRESSION_METHOD[1]);

		byte[] msg = baos.toByteArray();
		int msgLength = msg.length - 4;
		msg[3] = (byte) msgLength;
		msg[2] = (byte) (msgLength >> 8);
		msg[1] = (byte) (msgLength >> 16);

		updateHashes(msg);

		String encoded = new String(Base64.getEncoder().encode(msg));
		String randomClient = new String(Base64.getEncoder().encode(clientRandom));

		Tls clientHello = Tls.Hello("Client Hello", TlsHeadersClient.HEADER_CLIENT_HELLO,
				TlsHeadersClient.PROTOCOL_VERSION, 0, randomClient, TlsHeadersClient.CIPHER_SUITE,
				TlsHeadersClient.COMPRESSION_METHOD, encoded);

		ObjectMapper mapperWrite = new ObjectMapper();
		String messageAsJSONstring = mapperWrite.writeValueAsString(clientHello);
		recordLayer.sendHandshakeMessage(messageAsJSONstring, RecordLayerClient.handshakeTypes.ClientHello);
	}

	/*
	 * post request to send client key exchange to the server
	 * preparing the contents to be sent through the record layer 
	 */
	private static void doPostSendClientKeyExchange() throws IOException {

		byte[] preMasterSecret = new byte[48];

		randomGenerator.nextBytes(preMasterSecret);

		System.arraycopy(TlsHeadersClient.PROTOCOL_VERSION_B, 0, preMasterSecret, 0, 2);

		byte[] encrypted_masterSecret = rsa.encrypt(preMasterSecret);
		byte[] header = { TlsHeadersClient.HEADER_CLIENT_KEY_EXCHANGE, 0x00, 0x00, 0x00 };

		baos.reset();
		baos.write(header);
		baos.write(new byte[] { (byte) (encrypted_masterSecret.length >> 8), (byte) encrypted_masterSecret.length });
		baos.write(encrypted_masterSecret);

		byte[] msg = baos.toByteArray();
		int msgLength = msg.length - 4;
		msg[1] = (byte) (msgLength >> 16);
		msg[2] = (byte) (msgLength >> 8);
		msg[3] = (byte) msgLength;

		updateHashes(msg);

		String encryptedKey = new String(Base64.getEncoder().encode(encrypted_masterSecret));
		String encoded = new String(Base64.getEncoder().encode(msg));

		ClientKeyEXchange clientKeyEx = ClientKeyEXchange.clientKey("Client Key Exchange",
				TlsHeadersClient.HEADER_CLIENT_KEY_EXCHANGE, encrypted_masterSecret.length, encryptedKey, encoded);

		ObjectMapper mapperWrite = new ObjectMapper();
		String messageAsJSONstring = mapperWrite.writeValueAsString(clientKeyEx);

		recordLayer.sendHandshakeMessage(messageAsJSONstring, RecordLayerClient.handshakeTypes.ClientKeyExchange);

		generateMasterSecret(preMasterSecret);
		generateKeys();

		System.out.println("Sent Client Key Exchange");
		System.out.println("Generated Master Key");

	}

	/*
	 * post request to send change cipher spec to the server
	 * preparing the contents to be sent through the record layer 
	 */
	private static void doPostsendChangeCipherSpec() throws IOException {

		byte[] spec = new byte[] { 1 };

		String encoded = new String(Base64.getEncoder().encode(spec));

		ChangeCipherSpec cSpec = ChangeCipherSpec.changecipherSpec("Change Cipher Spec",
				TlsHeadersClient.CONTENTTYPE_CHANGE_CIPHER_SPEC, encoded);

		ObjectMapper mapperWrite = new ObjectMapper();
		String messageAsJSONstring = mapperWrite.writeValueAsString(cSpec);

		recordLayer.sendHandshakeMessage(messageAsJSONstring, RecordLayerClient.handshakeTypes.ChangeCipherSpec);

		System.out.println("Sent Client Cipher Spec Change");

	}

	/*
	 * post request to send finished to the server
	 * preparing the contents to be sent through the record layer 
	 */
	private static void doPostsendFinished() throws IOException, CloneNotSupportedException {

		byte[] header = { TlsHeadersClient.HEADER_FINISHED, 0x00, 0x00, 0x0C };
		baos.reset();
		baos.write(header);

		byte[] temp = new byte[36];
		tempMD = (MessageDigest) md5.clone();
		System.arraycopy(tempMD.digest(), 0, temp, 0, 16);
		tempMD = (MessageDigest) sha.clone();
		System.arraycopy(tempMD.digest(), 0, temp, 16, 20);

		baos.write(prf.getBytes(masterSecret, "client finished", temp, 12));

		byte[] msg = baos.toByteArray();

		updateHashes(msg);

		byte[] encrypted = recordLayer.sendMessage(RecordLayerClient.CONTENTTYPE_HANDSHAKE, msg);

		String encoded = new String(Base64.getEncoder().encode(encrypted));

		SendFinished Sfinished = SendFinished.sendFinished("Client Send Finished", "Client Send Finished", encoded);

		ObjectMapper mapper = new ObjectMapper();
		String messageAsJSONstring = mapper.writeValueAsString(Sfinished);
		recordLayer.sendHandshakeMessage(messageAsJSONstring, RecordLayerClient.handshakeTypes.SendFinished);

	}

	/*
	 * Private method to generate random bytes
	 * @param: 
	 * @return: byte array
	 */
	public static byte[] getRandom() {
		byte[] random = new byte[32];
		randomGenerator.nextBytes(random);
		return random;
	}

	/*
	 * Private method for MD5 and SHA hashing
	 * @param: byte array
	 * @return: void
	 */
	public static void updateHashes(byte[] message) {
		md5.update(message);
		sha.update(message);
	}

	/*
	 * Generate a master secret from the given preMasterSecret and store it in
	 * SecurityParameters
	 */
	private static void generateMasterSecret(byte[] preMasterSecret) throws TlsException {
		byte[] randoms = new byte[64];
		System.arraycopy(clientRandom, 0, randoms, 0, 32);
		System.arraycopy(TlsHeadersServer.serverRandom, 0, randoms, 32, 32);
		masterSecret = prf.getBytes(preMasterSecret, "master secret", randoms, 48);
	}

	/*
	 * Generate read and write keys for the Record layer using the MasterSecret
	 * stored in SecurityParameters.
	 */
	private static void generateKeys() throws TlsException {
		byte[] randoms = new byte[64];

		System.arraycopy(TlsHeadersServer.serverRandom, 0, randoms, 0, 32);
		System.arraycopy(clientRandom, 0, randoms, 32, 32);
		byte[] keyBlock = prf.getBytes(masterSecret, "key expansion", randoms, KEY_BLOCK_LENGTH);
		// set write MAC secrets
		recordLayer.setKeyBlock(TlsHeadersClient.cipherSuite, keyBlock);
	}

}
