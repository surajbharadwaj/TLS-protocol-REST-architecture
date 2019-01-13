package mobile.computing.ws1819;

public class SendFinished {
	
	/*
	 * To indicate the name of handshake message
	 * Type: string
	 */	
	private String handshakeProtocol;
	
	/*
	 * To indicate the value of the handshake protocol
	 * Type: string
	 */
	private String handshakeType;
	
	/*
	 * To store the encrypted message from recordlayer which is encoded SendFinished content for md5 and SHA update which will be required for verification at the end of finished message
	 * Type: string
	 */
	private String encoded;

	/*
	 * To set the HandshakeProtocol attribute
	 * @param: string
	 * @return: void
	 */
	private void setHandshakeProtocol(String HP) {
		this.handshakeProtocol = HP;
	}

	/*
	 * To set the handshakeType attribute
	 * @param: string
	 * @return: void
	 */
	private void setHandshakeType(String HT) {
		this.handshakeType = HT;
	}

	/*
	 * To set the encoded attribute
	 * @param: string
	 * @return: void
	 */
	private void setencoded(String mDE) {
		this.encoded = mDE;
	}

	/*
	 * To get the HandshakeProtocol attribute
	 * @param: 
	 * @return: string
	 */
	public String getHandshakeProtocol() {
		return handshakeProtocol;
	}

	/*
	 * To get the HandshakeType attribute
	 * @param: 
	 * @return: String
	 */
	public String getHandshakeType() {
		return handshakeType;
	}
	
	/*
	 * To get the encoded attribute
	 * @param: 
	 * @return: String
	 */
	public String getencoded() {
		return encoded;
	}

	/*
	 * To create new object of class SendFinished
	 * @param: String,String,String
	 * @return: SendFinished
	 */
	public static SendFinished sendFinished(String HP, String HT, String MDE) {
		SendFinished cSFinished = new SendFinished();

		cSFinished.setHandshakeProtocol(HP);
		cSFinished.setHandshakeType(HT);
		cSFinished.setencoded(MDE);
		return cSFinished;
	}

}
