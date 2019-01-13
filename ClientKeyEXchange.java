package mobile.computing.ws1819;

public class ClientKeyEXchange {
	
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
	 * To store the length of the mastersecret key
	 * Type: Integer
	 */
	private int Length;
	
	/*
	 * To store the encrypted mastersecret key 
	 * Type: string
	 */
	private String byteData;
	
	/*
	 * To store the encoded ClientKey Exchange content for md5 and SHA update which will be required for verification at the end of finished message
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
	 * To set the length of the mastersecret key
	 * @param: integer
	 * @return: void
	 */
	private void setLength(int Len)
	{
		this.Length=Len;
	}
	
	/*
	 * To set the Encoded attribute
	 * @param: string
	 * @return: void
	 */	
	private void setencoded(String mDE)
	{
		this.encoded=mDE;
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
	 * To get the mastersecret key length attribute
	 * @param: 
	 * @return: integer
	 */
	public int getLength()
	{
		return Length;
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
	 * To create new object of class ClientKeyEXchange
	 * @param: String,integer,integer,String,String
	 * @return: ClientKeyEXchange
	 */
	public static ClientKeyEXchange clientKey(String HP, int HT, int Len,String BD,String MDE)
	{
		ClientKeyEXchange clientKey = new ClientKeyEXchange();
		
		clientKey.setHandshakeProtocol(HP);
		clientKey.setHandshakeType(HT);
		clientKey.setLength(Len);
		clientKey.setbyteData(BD);
		clientKey.setencoded(MDE);
		return clientKey;
	}



}
