package mobile.computing.ws1819;



public class ServerCertificate {

	/*
	 * To indicate the name of handshake message
	 * Type: string
	 */
	private String handshakeProtocol;
	
	/*
	 * To indicate the value of the handshake protocol
	 * Type: integer
	 */
	private int handshakeType;
	
	/*
	 * To store the length of the certificate
	 * Type: Integer
	 */
	private int certificateLength;
	
	/*
	 * To store the encrypted certificate content which contains the public key
	 * Type: string
	 */
	private String byteData;
	
	/*
	 * To store the encoded server certificate content for md5 and SHA update which will be required for verification at the end of finished message
	 * Type: string
	 */
	private String encoded;
	
	/*
	 * To set the HandshakeProtocol attribute
	 * @param: string
	 * @return: void
	 */
	private void setHandshakeProtocol(String HP)
	{
		this.handshakeProtocol = HP;
	}
	
	/*
	 * To set the HandshakeType attribute
	 * @param: integer
	 * @return: void
	 */
	private void setHandshakeType(int HT)
	{
		this.handshakeType = HT;
	}
	
	/*
	 * To set the CertificateLength attribute
	 * @param: integer
	 * @return: void
	 */
	private void setcertificateLength(int CL)
	{
		this.certificateLength=CL;
	}
	
	/*
	 * To set the ByteData attribute
	 * @param: string
	 * @return: void
	 */
	private void setbyteData(String BD)
	{
		this.byteData=BD;
	}
	
	/*
	 * To set the Encoded attribute
	 * @param: string
	 * @return: void
	 */
	private void setencoded(String mDE) {
		
		this.encoded=mDE;
	}
    
	/*
	 * To get the HandshakeProtocol attribute
	 * @param: 
	 * @return: string
	 */
	public String getHandshakeProtocol()
	{
		return handshakeProtocol;
	}
	
	/*
	 * To get the HandshakeType attribute
	 * @param: 
	 * @return: integer
	 */
	public int getHandshakeType()
	{
		return handshakeType;
	}
	
	/*
	 * To get the CertificateLength attribute
	 * @param: 
	 * @return: integer
	 */
	public int getCertificateLength()
	{
		return certificateLength;
	}
	
	/*
	 * To get the byteData attribute
	 * @param: 
	 * @return: string
	 */
	public String getbyteData()
	{
		return byteData;
	}
	
	/*
	 * To get the encoded attribute
	 * @param: 
	 * @return: string
	 */
	public String getencoded()
	{
		return encoded;
	}
	
	/*
	 * To create new object of class servercertificate
	 * @param: String,integer,integer,String,String
	 * @return: ServerCertificate
	 */
	public static ServerCertificate certificateServer(String HP, int HT, int CL,String BD,String MDE)
	{
		ServerCertificate certificateServer = new ServerCertificate();
		
		certificateServer.setHandshakeProtocol(HP);
		certificateServer.setHandshakeType(HT);
		certificateServer.setcertificateLength(CL);
		certificateServer.setbyteData(BD);
		certificateServer.setencoded(MDE);
		return certificateServer;
	}

	
	
}

