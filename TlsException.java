package mobile.computing.ws1819;

import java.io.IOException;


public class TlsException extends IOException {
	
	/*
	 * To ensure that a loaded class corresponds exactly to a serialized object. 
	 * If no match is found, then an InvalidClassException is thrown.
	 * Type: long
	 */
	private static final long serialVersionUID = 1L;

	/*
	 * class constructor
	 */
	public TlsException(String message) {
		super(message);
	}

}
