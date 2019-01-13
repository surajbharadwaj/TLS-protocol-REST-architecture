package mobile.computing.ws1819;

public class ChangeCipherSpec {
	
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
	 * To store the encoded ChangeCipherSpec of  value 1 
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
	 * To set the Encoded attribute
	 * @param: string
	 * @return: void
	 */
	private void setencoded(String BD)
	{
		this.encoded=BD;
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
	 * To get the encoded attribute
	 * @param: 
	 * @return: string
	 */
	public String getencoded()
	{
		return encoded;
	}
	
	/*
	 * To create new object of class ChangeCipherSpec
	 * @param: String,integer,String
	 * @return: ChangeCipherSpec
	 */
	public static ChangeCipherSpec changecipherSpec(String HP, int HT,String BD)
	{
		ChangeCipherSpec cipherSpec = new ChangeCipherSpec();
		
		cipherSpec.setHandshakeProtocol(HP);
		cipherSpec.setHandshakeType(HT);
		cipherSpec.setencoded(BD);
		return cipherSpec;
	}


	
}
