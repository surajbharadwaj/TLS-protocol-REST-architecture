package mobile.computing.ws1819.client;

import java.io.IOException;

import mobile.computing.ws1819.ApplicationData;
import mobile.computing.ws1819.ChangeCipherSpec;
import mobile.computing.ws1819.SendFinished;
import mobile.computing.ws1819.ServerCertificate;
import mobile.computing.ws1819.ServerHelloDone;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import mobile.computing.ws1819.client.TlsHeadersClient;
import mobile.computing.ws1819.server.TlsHeadersServer;
import mobile.computing.ws1819.TlsException;
import mobile.computing.ws1819.Tls;

@Path("messageclient")
public class ClientMessageResource {

	/*
	 * To process the Server Hello message sent by the server in response to Client
	 * Hello message This method carries out error checking Returns ok if the
	 * process is successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/ServerHello")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String createMessage(String messageAsJSONstring) throws Exception {

		System.out.println("Sent Client Hello Message");

		ObjectMapper mapperRead = new ObjectMapper();

		Tls tlsServerHello = mapperRead.readValue(messageAsJSONstring, Tls.class);

		if (tlsServerHello.getHandshakeType() != TlsHeadersClient.HEADER_SERVER_HELLO) {
			throw new TlsException("Did not get the expected ServerHello message ,Handshake Failure");
		}

		String protocolVersion = Arrays.toString(TlsHeadersClient.PROTOCOL_VERSION);

		if (!Arrays.toString(tlsServerHello.getVersion()).equals(protocolVersion)) {

			throw new TlsException("Bad ProtocolVersion in ServertHello");
		}

		System.out.println("Received Server Hello Message");

		TlsHeadersServer.serverRandom = Base64.getDecoder().decode((tlsServerHello.getRandom()));

		TlsHeadersClient.cipherSuite = tlsServerHello.getCipherSuite()[0];

		byte[] msg = Base64.getDecoder().decode(tlsServerHello.getEncoded());

		StartRestClient.updateHashes(msg);

		return "ok";
	}

	/*
	 * To process the Server Certificate message sent by the server. This method
	 * carries out error checking and extracts the RSA public key Returns ok if the
	 * process is successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/ServerCertificate")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String serverCertificate(String messageAsJSONstring)
			throws JsonParseException, JsonMappingException, IOException {

		ObjectMapper mapper = new ObjectMapper();
		ServerCertificate sercert = mapper.readValue(messageAsJSONstring, ServerCertificate.class);

		if (sercert.getHandshakeType() != TlsHeadersClient.HEADER_CERTIFICATE) {
			throw new TlsException("Did not get the expected Certificate message");
		}

		byte[] decoded = Base64.getDecoder().decode(sercert.getbyteData().getBytes());
		byte[] msg = Base64.getDecoder().decode(sercert.getencoded());

		int offset = 0;

		int len = sercert.getCertificateLength();

		StartRestClient.rsa.setCertificates(decoded, offset, len);

		StartRestClient.updateHashes(msg);

		System.out.println("Received Server Certificate with public key");

		return "ok";
	}

	/*
	 * To process the Server Hello Done message sent by the server immedietely after
	 * the Server Certificate message This method carries out error checking Returns
	 * ok if the process is successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/ServerHelloDone")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String serverHelloDone(String messageAsJSONstring)
			throws JsonParseException, JsonMappingException, IOException {

		ObjectMapper mapper = new ObjectMapper();
		ServerHelloDone serDone = mapper.readValue(messageAsJSONstring, ServerHelloDone.class);

		byte[] msg = Base64.getDecoder().decode(serDone.getencoded().getBytes());

		if (msg[0] != TlsHeadersClient.HEADER_SERVER_HELLO_DONE) {
			throw new TlsException("Did not get the expected ServerHelloDone message");
		}

		if (msg.length != 4 || msg[1] != 0x00 || msg[2] != 0x00 || msg[3] != 0x00) {
			throw new TlsException("Bad length in ServerHelloDone");
		}

		StartRestClient.updateHashes(msg);

		System.out.println("Received Server Hello Done");

		return "ok";
	}

	/*
	 * To process the Change Cipher Spec message sent by the server This method
	 * changes the serverWriteCipherIsNull flag Returns ok if the process is
	 * successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/ChangeCipherSpec")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String cipherSpec(String messageAsJSONstring) throws JsonParseException, JsonMappingException, IOException {

		ObjectMapper mapperspecserver = new ObjectMapper();
		ChangeCipherSpec SpecServer = mapperspecserver.readValue(messageAsJSONstring, ChangeCipherSpec.class);

		byte[] decoded = Base64.getDecoder().decode(SpecServer.getencoded().getBytes());

		if (decoded == null || decoded.length != 1 || decoded[0] != 0x01) {
			throw new TlsException("Got bad ChangeCipherSpec message");
		}

		StartRestClient.recordLayer.changeServerWriteState();

		System.out.println("Received Server Cipher Spec Change");

		return "ok";
	}

	/*
	 * To process the Server Send Finished message sent by the server to indicate
	 * that the handshake process is done This method carries out error checking
	 * Returns ok if the process is successful
	 * 
	 * @param: string
	 * 
	 * @return: string
	 */
	@POST
	@Path("/ServerSendFinished")
	@Produces(MediaType.TEXT_PLAIN)
	@Consumes(MediaType.APPLICATION_JSON)
	public String servFinished(String messageAsJSONstring)
			throws JsonParseException, JsonMappingException, IOException {

		ObjectMapper mapperFin = new ObjectMapper();
		SendFinished readserverFin = mapperFin.readValue(messageAsJSONstring, SendFinished.class);

		byte[] msg = Base64.getDecoder().decode(readserverFin.getencoded());
		byte[] data = StartRestClient.recordLayer.readRecord(msg);

		int offset = 0;

		if (data[offset] != TlsHeadersClient.HEADER_FINISHED) {
			throw new TlsException("Error in the expected Finished message");
		}

		offset += 4;

		if (data.length != 16) {
			throw new TlsException("Length field in Finished message Mismatch");
		}

		byte[] temp2 = new byte[36];

		try {

			StartRestClient.tempMD = (MessageDigest) StartRestClient.md5.clone();
			System.arraycopy(StartRestClient.tempMD.digest(), 0, temp2, 0, 16);
			StartRestClient.tempMD = (MessageDigest) StartRestClient.sha.clone();
			System.arraycopy(StartRestClient.tempMD.digest(), 0, temp2, 16, 20);
		} catch (Exception e) {
			e.printStackTrace();
			throw new TlsException("Error cloning message digest in Handshake.readFinsihed()");
		}

		byte[] expected = StartRestClient.prf.getBytes(StartRestClient.masterSecret, "server finished", temp2, 12);

		for (int i = 0; i < 12; i++) {
			if (data[i + 4] != expected[i]) {
				throw new TlsException("Bad Handshake VerifyData from Server");
			}
		}

		StartRestClient.updateHashes(msg);

		System.out.println("Received Server Finished");

		return "ok";
	}

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

		System.out.println("\nRecived Encrypted from Server: " + receivedEncrypted);

		byte[] decoded = StartRestClient.recordLayer.readRecord(msg);

		String data = new String(decoded);

		System.out.println("Decrypted: " + data);

		return "ok";
	}

}