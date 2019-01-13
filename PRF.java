package mobile.computing.ws1819;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import mobile.computing.ws1819.HMAC;

/***
 * Pseudo Random Function
 */
public class PRF {

	private MessageDigest sha = null;
	private HMAC hmac = null;

	/**
	 * Class constructor.
	 */
	public PRF() throws TlsException {
		try {
			sha = MessageDigest.getInstance("SHA");
			hmac = new HMAC(null, null);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new TlsException("Error in PRF.  Could not create message digests: " + e.getMessage());
		}
	}

	/**
	 * Generates the PRF of the given inputs
	 * 
	 * @param secret
	 * @param label
	 * @param seed
	 * @param length The length of the output to generate.
	 * @return PRF of inputs
	 */
	public byte[] getBytes(byte[] secret, String label, byte[] seed, int length) throws TlsException {

		// split secret into S1 and S2
		int lenS1 = secret.length / 2 + secret.length % 2;

		byte[] S1 = new byte[lenS1];
		byte[] S2 = new byte[lenS1];

		System.arraycopy(secret, 0, S1, 0, lenS1);
		System.arraycopy(secret, secret.length - lenS1, S2, 0, lenS1);

		// get the seed as concatenation of label and seed
		byte[] labelAndSeed = new byte[label.length() + seed.length];
		System.arraycopy(label.getBytes(), 0, labelAndSeed, 0, label.length());
		System.arraycopy(seed, 0, labelAndSeed, label.length(), seed.length);

		byte[] shaOutput = p_hash(sha, 20, S2, labelAndSeed, length);

		return shaOutput;
	}

	/**
	 * Perform the P_hash function
	 * 
	 * @param md           The MessageDigest function to use
	 * @param digestLength The length of output from the given digest
	 * @param secret       The TLS secret
	 * @param seed         The seed to use
	 * @param length       The desired length of the output.
	 * @return The P_hash of the inputs.
	 */
	private byte[] p_hash(MessageDigest md, int digestLength, byte[] secret, byte[] seed, int length)
			throws TlsException {

		// set up our hmac
		hmac.setMD(md);
		hmac.setKey(secret);

		byte[] output = new byte[length]; // what we return
		int offset = 0; // how much data we have created so far
		int toCopy = 0; // the amount of data to copy from current HMAC

		byte[] A = seed; // initialise A(0)

		// concatenation of A and seed
		byte[] A_seed = new byte[digestLength + seed.length];
		System.arraycopy(seed, 0, A_seed, digestLength, seed.length);

		byte[] tempBuf = null;

		// continually perform HMACs and concatenate until we have enough output
		while (offset < length) {

			// calculate the A to use.
			A = hmac.digest(A);

			// concatenate A and seed and perform HMAC
			System.arraycopy(A, 0, A_seed, 0, digestLength);
			tempBuf = hmac.digest(A_seed);

			// work out how much needs to be copied and copy it
			toCopy = tempBuf.length < (length - offset) ? tempBuf.length : length - offset;
			System.arraycopy(tempBuf, 0, output, offset, toCopy);
			offset += toCopy;
		}
		return output;
	}

}
