package mobile.computing.ws1819.server;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import mobile.computing.ws1819.FileLoad;
import mobile.computing.ws1819.PRF;

import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;

import mobile.computing.ws1819.SendFinished;
import mobile.computing.ws1819.Tls;
import mobile.computing.ws1819.TlsException;
import mobile.computing.ws1819.client.RecordLayerClient;
import mobile.computing.ws1819.server.RsaServer;
import mobile.computing.ws1819.ServerCertificate;
import mobile.computing.ws1819.ServerHelloDone;
import mobile.computing.ws1819.ApplicationData;
import mobile.computing.ws1819.ChangeCipherSpec;
import mobile.computing.ws1819.ClientKeyEXchange;
import mobile.computing.ws1819.server.RecordLayerServer;

@Path("message")
public class ServerMessageResource {

	private static ByteArrayOutputStream baos;
	private static Random randomGenerator;
	private static RsaServer rsa;
	private static PRF prf;
	private static MessageDigest md5;
	private static MessageDigest sha;
	private static MessageDigest tempMD;
	private static byte[] serverRandom;
	private static RecordLayerServer recordLayer;
	private static byte[] masterSecret;

	/*
	 * To process the Client Hello message sent by the Client This method carries
	 * out error checking After the error checking, three post requests are made for
	 * Server Hello, Server Certificate and Server Hello Done in the same order
	 * Returns ok if the process is successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/ClientHello")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String createMessage(String messageAsJSONstring) throws Exception {
		randomGenerator = new Random();
		md5 = MessageDigest.getInstance("MD5");
		sha = MessageDigest.getInstance("SHA");
		rsa = new RsaServer();
		recordLayer = new RecordLayerServer();
		baos = new ByteArrayOutputStream();
		prf = new PRF();

		String recordlayerMessage = recordLayer.readHandshakeMessage(messageAsJSONstring);

		ObjectMapper mapper = new ObjectMapper();
		Tls tlsClientHello = mapper.readValue(recordlayerMessage, Tls.class);

		byte[] msg = Base64.getDecoder().decode(tlsClientHello.getEncoded());

		updateHashes(msg);

		String protocolVersion = Arrays.toString(TlsHeadersServer.PROTOCOL_VERSION);

		if (!Arrays.toString(tlsClientHello.getVersion()).equals(protocolVersion)) {
			throw new TlsException(" ProtocolVersion not supported in ClientHello");
		}

		if (tlsClientHello.getHandshakeType() != TlsHeadersServer.HEADER_CLIENT_HELLO) {
			throw new TlsException("Didn't Receive ClientHello message");
		}

		System.out.println("Received Client Hello Message");

		TlsHeadersServer.clientRandom = new byte[32];

		TlsHeadersServer.clientRandom = Base64.getDecoder().decode((tlsClientHello.getRandom()));

		TlsHeadersServer.sessionId = tlsClientHello.getSessionId();

		TlsHeadersServer.clientCipherSuites = tlsClientHello.getCipherSuite();

		byte[] header = { TlsHeadersServer.HEADER_SERVER_HELLO, 0x00, 0x00, 0x00 };
		serverRandom = getRandom();

		baos.reset();
		baos.write(header);
		baos.write(TlsHeadersServer.PROTOCOL_VERSION_B);
		baos.write(serverRandom);

		String randomServer = new String(Base64.getEncoder().encode(serverRandom));

		boolean isExist = false;

		for (int i = 0; i < TlsHeadersServer.clientCipherSuites.length; i++) {
			if (TlsHeadersServer.clientCipherSuites[i] == rsa.CIPHER_SUITE)
				isExist = true;
		}

		if (!isExist) {

			Tls serverHello = Tls.Hello("Server Hello", TlsHeadersServer.ALERT_HANDSHAKE_FAILURE,
					TlsHeadersServer.PROTOCOL_VERSION, 0, randomServer, new int[] { 0 }, new int[] { 0 }, null);

			ObjectMapper mapperWriteError = new ObjectMapper();
			String messageAsJSONstringError = mapperWriteError.writeValueAsString(serverHello);
			recordLayer.sendHandshakeMessage(messageAsJSONstringError, RecordLayerServer.handshakeTypes.ServerHello);

			System.out.println("Sent Server Hello Message but error");

		} else {
			byte[] bCipherSuite = new byte[2];
			bCipherSuite[1] = (byte) rsa.CIPHER_SUITE;
			bCipherSuite[0] = (byte) (rsa.CIPHER_SUITE >> 8);

			baos.write(bCipherSuite);

			byte[] msg1 = baos.toByteArray();
			int msg1Length = msg1.length - 4;
			msg1[3] = (byte) msg1Length;
			msg1[2] = (byte) (msg1Length >> 8);
			msg1[1] = (byte) (msg1Length >> 16);

			updateHashes(msg1);

			String encoded = new String(Base64.getEncoder().encode(msg1));

			int[] serverCipherSuite = new int[] { rsa.CIPHER_SUITE };

			Tls serverHello = Tls.Hello("Server Hello", TlsHeadersServer.HEADER_SERVER_HELLO,
					TlsHeadersServer.PROTOCOL_VERSION, 0, randomServer, serverCipherSuite,
					TlsHeadersServer.COMPRESSION_METHOD, encoded);

			ObjectMapper mapperWrite = new ObjectMapper();
			String messageAsJSONstringWrite = mapperWrite.writeValueAsString(serverHello);

			recordLayer.sendHandshakeMessage(messageAsJSONstringWrite, RecordLayerServer.handshakeTypes.ServerHello);

			System.out.println("Sent Server Hello Message");

			int certLength;
			byte[] certificate = null;

			try {
				certificate = loadCertificateFromFile();
			} catch (Exception e) {

				e.printStackTrace();
			}

			certLength = certificate.length - 4;

			byte[] headercert = { TlsHeadersServer.HEADER_CERTIFICATE, 0x00, 0x00, 0x00 };

			baos.reset();
			baos.write(headercert);

			byte[] bCertLength = new byte[3];
			bCertLength[2] = (byte) certLength;
			bCertLength[1] = (byte) (certLength >> 8);
			bCertLength[0] = (byte) (certLength >> 16);

			baos.write(bCertLength);
			baos.write(certificate);

			byte[] msg2 = baos.toByteArray();
			int msgLength = msg2.length - 4;
			msg2[3] = (byte) msgLength;
			msg2[2] = (byte) (msgLength >> 8);
			msg2[1] = (byte) (msgLength >> 16);

			updateHashes(msg2);

			String encoded2 = new String(Base64.getEncoder().encode(msg2));
			String encodedCertificateMessage = new String(Base64.getEncoder().encode(certificate));

			ServerCertificate serCer = ServerCertificate.certificateServer("Server Certificate",
					TlsHeadersServer.HEADER_CERTIFICATE, certLength, encodedCertificateMessage, encoded2);

			ObjectMapper mapperCert = new ObjectMapper();
			String messageAsJSONstringCert = mapperCert.writeValueAsString(serCer);

			recordLayer.sendHandshakeMessage(messageAsJSONstringCert,
					RecordLayerServer.handshakeTypes.ServerCertificate);

			System.out.println("Sent Server Certificate with public key");

			baos.reset();

			byte[] headerServerDone = { TlsHeadersServer.HEADER_SERVER_HELLO_DONE, 0x00, 0x00, 0x00 };

			try {
				baos.write(headerServerDone);
			} catch (Exception e) {
				e.printStackTrace();
				throw new TlsException("Error in Handshake.sendClientHello: " + e.getMessage());
			}

			byte[] msg3 = baos.toByteArray();

			updateHashes(msg3);

			String encoded3 = new String(Base64.getEncoder().encode(msg3));

			ServerHelloDone helloDone = ServerHelloDone.SHelloDone("Server Hello Done",
					TlsHeadersServer.HEADER_SERVER_HELLO_DONE, encoded3);

			ObjectMapper mapperHelloDone = new ObjectMapper();
			String messageAsJSONstringHelloDone = mapperHelloDone.writeValueAsString(helloDone);

			recordLayer.sendHandshakeMessage(messageAsJSONstringHelloDone,
					RecordLayerServer.handshakeTypes.ServerHelloDone);

			System.out.println("Server Hello Done");

		}

		return "ok";
	}

	/*
	 * To process the Client Key Exchange message sent by the Client This method
	 * carries out error checking After the error checking, based on the Pre-master
	 * secret key, Mater secret key is generated Returns ok if the process is
	 * successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/ClientKeyExchange")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String clientKeyExchange(String messageAsJSONstring)
			throws JsonParseException, JsonMappingException, IOException {

		String recordlayerMessage = recordLayer.readHandshakeMessage(messageAsJSONstring);

		ObjectMapper mapper = new ObjectMapper();
		ClientKeyEXchange cKey = mapper.readValue(recordlayerMessage, ClientKeyEXchange.class);

		if (cKey.getHandshakeType() != TlsHeadersServer.HEADER_CLIENT_KEY_EXCHANGE) {
			throw new TlsException("Wrong  ClientKeyExchange message");
		}

		int encryptedLength = cKey.getLength();

		byte[] enryptedKey = new byte[encryptedLength];

		byte[] preMasterSecret;

		enryptedKey = Base64.getDecoder().decode(cKey.getbyteData());

		byte[] msg = Base64.getDecoder().decode(cKey.getencoded());

		try {
			preMasterSecret = rsa.decrypt(enryptedKey);
		} catch (Exception e) {
			throw new TlsException("PreMasterSecret cannot be decrypted. Exception" + e.getMessage());
		}

		if (preMasterSecret[0] != TlsHeadersServer.PROTOCOL_VERSION_B[0]
				|| preMasterSecret[1] != TlsHeadersServer.PROTOCOL_VERSION_B[1]) {
			throw new TlsException("Bad ProtocolVersion in ClientKeyExchange");
		}

		System.out.println("Received Client Key Exchange");

		generateMasterSecret(preMasterSecret);

		generateKeys();

		System.out.println("Generated Master Key");

		updateHashes(msg);

		return "OK";
	}

	/*
	 * To process the Change Cipher Suite message sent by the Client This method
	 * carries out error checking After the error checking, this method changes the
	 * clientWriteCipherIsNull flag Returns ok if the process is successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/ChangeCipherSpec")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String changeCipherSpec(String messageAsJSONstring)
			throws JsonParseException, JsonMappingException, IOException {

		String recordlayerMessage = recordLayer.readHandshakeMessage(messageAsJSONstring);

		ObjectMapper mapper = new ObjectMapper();
		ChangeCipherSpec cSpecServer = mapper.readValue(recordlayerMessage, ChangeCipherSpec.class);

		byte[] msg = Base64.getDecoder().decode(cSpecServer.getencoded());

		if (msg == null || msg.length != 1 || msg[0] != 0x01) {
			throw new TlsException("Corrupted ChangeCipherSpec message");
		}

		recordLayer.changeClientWriteState();

		System.out.println("Received Client Cipher Spec Change");

		return "Ok";

	}

	/*
	 * To process the Send Finished message sent by the Client This method carries
	 * out error checking After the error checking, two post requests are made for
	 * Change Cipher spec and server send finished in the same order Returns ok if
	 * the process is successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/SendFinished")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String readFinished(String messageAsJSONstring)
			throws JsonParseException, JsonMappingException, IOException, CloneNotSupportedException {

		ObjectMapper mapper = new ObjectMapper();
		SendFinished readFin = mapper.readValue(messageAsJSONstring, SendFinished.class);

		byte[] msg = Base64.getDecoder().decode(readFin.getencoded());

		byte[] decoded = recordLayer.readRecord(msg);

		int offset = 0;

		if (decoded[offset] != TlsHeadersServer.HEADER_FINISHED) {
			throw new TlsException("Error in  the expected Finished message");
		}

		offset += 4;

		if (decoded.length != 16) {
			throw new TlsException("Length field in Finished message Mismatch");
		}

		byte[] temp = new byte[36];
		try {

			tempMD = (MessageDigest) md5.clone();
			System.arraycopy(tempMD.digest(), 0, temp, 0, 16);
			tempMD = (MessageDigest) sha.clone();
			System.arraycopy(tempMD.digest(), 0, temp, 16, 20);
		} catch (Exception e) {
			e.printStackTrace();
			throw new TlsException("Error cloning message digest in Handshake.readFinsihed()");
		}

		byte[] shouldBe = prf.getBytes(masterSecret, "client finished", temp, 12);

		// verify the 12 bytes
		for (int i = 0; i < 12; i++) {
			if (decoded[i + 4] != shouldBe[i]) {
				throw new TlsException("Bad Handshake VerifyData from Server");
			}
		}

		updateHashes(decoded);

		System.out.println("Recieved Client finished");

		byte[] spec = new byte[] { 1 };

		String byteDataEncoded = new String(Base64.getEncoder().encode(spec));

		ChangeCipherSpec serverChangeSpec = ChangeCipherSpec.changecipherSpec("Change Cipher Spec",
				RecordLayerServer.CONTENTTYPE_CHANGE_CIPHER_SPEC, byteDataEncoded);

		ObjectMapper mapperWrite = new ObjectMapper();
		String messageAsJSONstringspec = mapperWrite.writeValueAsString(serverChangeSpec);

		recordLayer.sendHandshakeMessage(messageAsJSONstringspec, RecordLayerServer.handshakeTypes.ChangeCipherSpec);

		System.out.println("Sent Cipher Spec Change");

		byte[] header = { TlsHeadersServer.HEADER_FINISHED, 0x00, 0x00, 0x0C };

		baos.reset();
		baos.write(header);

		// concatenate MD5(handshake_messages) and SHA(handshake_messages)
		byte[] temp2 = new byte[36];
		tempMD = (MessageDigest) md5.clone();
		System.arraycopy(tempMD.digest(), 0, temp2, 0, 16);
		tempMD = (MessageDigest) sha.clone();
		System.arraycopy(tempMD.digest(), 0, temp2, 16, 20);

		baos.write(prf.getBytes(masterSecret, "server finished", temp2, 12));

		byte[] msg2 = baos.toByteArray();

		updateHashes(msg2);

		byte[] md5encod = recordLayer.sendMessage(RecordLayerServer.CONTENTTYPE_HANDSHAKE, msg2);

		String encoded = new String(Base64.getEncoder().encode(md5encod));

		SendFinished Serverfinished = SendFinished.sendFinished("Server Send Finished", "Server Send Finished",
				encoded);

		ObjectMapper mapperFinished = new ObjectMapper();
		String messageAsJSONstringFin = mapperFinished.writeValueAsString(Serverfinished);

		recordLayer.sendHandshakeMessage(messageAsJSONstringFin, RecordLayerServer.handshakeTypes.SendFinished);

		System.out.println("Sent Server Finished Done");

		return "ok";
	}

	/*
	 * To process the Application Data message sent by the Client Here the recieved
	 * encrypted message is decrypted and displayed on the console Returns ok if the
	 * process is successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/ApplicationData")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String appData(String messageAsJSONstring)
			throws JsonParseException, JsonMappingException, IOException, CloneNotSupportedException {

		ObjectMapper mapper = new ObjectMapper();
		ApplicationData appdata = mapper.readValue(messageAsJSONstring, ApplicationData.class);

		byte[] msg = Base64.getDecoder().decode(appdata.getencoded());
		String receivedEncrypted = new String(Base64.getEncoder().encode(msg));

		System.out.println("\nRecived Encrypted from client: " + receivedEncrypted);

		byte[] decoded = recordLayer.readRecord(msg);

		String data = new String(decoded);

		System.out.println("Decrypted: " + data);

		String input = null;

		BufferedReader console = new BufferedReader(new InputStreamReader(System.in));
		System.out.print("\nType message: ");
		input = console.readLine();
		byte[] message = input.getBytes();
		recordLayer.changeServerWriteState();
		byte[] md5encoded = recordLayer.sendMessage(RecordLayerClient.CONTENTTYPE_APPLICATION_DATA, message);

		String encoded = new String(Base64.getEncoder().encode(md5encoded));

		ApplicationData sendData = ApplicationData.data("Application Data", encoded);

		ObjectMapper mapperData1 = new ObjectMapper();
		String messageAsJSONstringSend = mapperData1.writeValueAsString(sendData);

		Client create = Client.create();
		WebResource service = create.resource("http://127.0.0.1:8089/api");

		@SuppressWarnings("unused")
		String response = service.path("messageclient/ApplicationData").type(MediaType.APPLICATION_JSON)
				.post(String.class, messageAsJSONstringSend);
		return "ok";
	};

	/*
	 * Private method to generate master secret key based on random numbers
	 * generated by client and server
	 * 
	 * @param: byte array
	 * 
	 * @return: void
	 */
	private static void generateMasterSecret(byte[] preMasterSecret) throws TlsException {
		byte[] randoms = new byte[64];
		System.arraycopy(TlsHeadersServer.clientRandom, 0, randoms, 0, 32);
		System.arraycopy(serverRandom, 0, randoms, 32, 32);

		masterSecret = prf.getBytes(preMasterSecret, "master secret", randoms, 48);

	}

	/*
	 * Private method to generate keys which is used for further encryption
	 * 
	 * @param:
	 * 
	 * @return: void
	 */
	private static void generateKeys() throws TlsException {
		byte[] randoms = new byte[64];

		System.arraycopy(serverRandom, 0, randoms, 0, 32);
		System.arraycopy(TlsHeadersServer.clientRandom, 0, randoms, 32, 32);
		byte[] keyBlock = prf.getBytes(masterSecret, "key expansion", randoms, TlsHeadersServer.KEY_BLOCK_LENGTH);
//		System.out.println(Arrays.toString(keyBlock));
		recordLayer.setKeyBlock(rsa.CIPHER_SUITE, keyBlock);
	}

	/*
	 * Private method for MD5 and SHA hashing
	 * 
	 * @param: byte array
	 * 
	 * @return: void
	 */
	private static void updateHashes(byte[] message) {
		md5.update(message);
		sha.update(message);
	}

	/*
	 * Private method to generate random bytes
	 * 
	 * @param:
	 * 
	 * @return: byte array
	 */
	private static byte[] getRandom() {
		byte[] random = new byte[32];
		randomGenerator.nextBytes(random);
		return random;
	}

	/*
	 * Private method to import the certificate and casting it to X509 format and
	 * encoding it to byte
	 * 
	 * @param:
	 * 
	 * @return: byte array
	 */
	private static byte[] loadCertificateFromFile() throws Exception {

		InputStream ins = FileLoad.loadFileAsStream("/Certificate.cer");

		CertificateFactory cf;
		X509Certificate cert = null;

		try {
			cf = CertificateFactory.getInstance("X.509");
			cert = (X509Certificate) cf.generateCertificate(ins);
		} catch (CertificateException e1) {
			e1.printStackTrace();
		}

		return cert.getEncoded();

	}

}