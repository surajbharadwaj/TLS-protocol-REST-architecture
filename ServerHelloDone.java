package mobile.computing.ws1819;

public class ServerHelloDone {
	
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
	 * To store the encoded ServerHello Done content for md5 and SHA update which will be required for verification at the end of finished message
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
	 * To set the handshakeType attribute
	 * @param: string
	 * @return: void
	 */
	private void setHandshakeType(int HT)
	{
		this.handshakeType = HT;
	}
	
	
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
	 * To create new object of class ServerHelloDone
	 * @param: String,integer,String
	 * @return: ServerHelloDone
	 */
	public static ServerHelloDone SHelloDone(String HP, int HT,String BD)
	{
		ServerHelloDone shelloDone = new ServerHelloDone();
		
		shelloDone.setHandshakeProtocol(HP);
		shelloDone.setHandshakeType(HT);
		shelloDone.setencoded(BD);
		return shelloDone;
	}
}
