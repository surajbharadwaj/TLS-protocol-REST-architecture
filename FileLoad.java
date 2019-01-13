package mobile.computing.ws1819;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;


public class FileLoad {

	/*
	 * Loading the data from the file as byte and storing it as byte array
	 * @param: string
	 * @return: byte array
	 */
	public static byte[] loadFileAsBytesArray(String fileName) throws Exception {

		InputStream ins = loadFileAsStream(fileName);

		ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[16384];

		while ((nRead = ins.read(data, 0, data.length)) != -1) {
			buffer.write(data, 0, nRead);
		}

		buffer.flush();

		return buffer.toByteArray();

	}
	
	/*
	 * Fetch the resource with given name and stores it in the form of inputstream
	 * @param: string
	 * @return: InputStream
	 */
	public static InputStream loadFileAsStream(String fileName) {
		InputStream ins = FileLoad.class.getResourceAsStream(fileName);

		return ins;
	}
	
}
