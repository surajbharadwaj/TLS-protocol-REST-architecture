
package mobile.computing.ws1819.client;

import java.math.BigInteger;
import java.util.Random;

public class RsaClient {

	// Instance variables
	private byte[] certs;
	private int certsOffset;

	private BigInteger modulus;
	private BigInteger exponent;
	private int keysize;

	private Random random;

	public RsaClient() {
		random = new Random();
	}

	public void setCertificates(byte[] buf, int offset, int len) {
		certs = buf;
		certsOffset = offset;
		int asnlen = 0;

		// TBSCertificate
		for (int i = 0; i < 2; i++) {
			certsOffset++;
			asnlen = readLengthFromBuf();
		}

		// version
		if ((buf[certsOffset] & 0x80) > 0) {
			certsOffset++;
			certsOffset++;
			asnlen = readLengthFromBuf();
			certsOffset += asnlen;
		}

		// TBSCertificate - serialNumber, signature, issuer, validity, subject
		for (int i = 0; i < 5; i++) {
			certsOffset++;
			asnlen = readLengthFromBuf();
			certsOffset += asnlen;
		}

		// TBSCertificate - SubjectPublicKeyInfo
		certsOffset++;
		asnlen = readLengthFromBuf();
		// TBSCertificate - SubjectPublicKeyInfo - algorithm
		certsOffset++;
		asnlen = readLengthFromBuf();
		certsOffset += asnlen;

		// TBSCertificate - SubjectPublicKeyInfo - BitString
		certsOffset++;
		asnlen = readLengthFromBuf();

		// TBSCertificate - SubjectPublicKeyInfo - BitString - RSAPublicKey
		certsOffset++;
		certsOffset++;
		asnlen = readLengthFromBuf();

		// TBSCertificate - SubjectPublicKeyInfo - RSAPublicKey - modulus
		certsOffset++;
		int modLen = readLengthFromBuf();
		byte[] mod = new byte[modLen];
		System.arraycopy(certs, certsOffset, mod, 0, modLen);
		certsOffset += modLen;
		modulus = new BigInteger(1, mod);
		int i = 0;
		keysize = modLen;
		while (mod[i++] == 0) {
			keysize--;
		}

		// TBSCertificate - SubjectPublicKeyInfo - RSAPublicKey - exponent
		certsOffset++;
		int expLen = readLengthFromBuf();
		byte[] exp = new byte[expLen];
		System.arraycopy(certs, certsOffset, exp, 0, expLen);
		certsOffset += expLen;
		exponent = new BigInteger(1, exp);
	}

	public byte[] encrypt(byte[] in) {
		// pkcs1 padding
		byte[] temp = new byte[keysize - 1];
		for (int i = 0; i < temp.length; i++) {
			// make sure there are no bytes with value 0
			temp[i] = (byte) (random.nextInt(255) + 1);
		}
		temp[0] = 0x02;
		temp[temp.length - in.length - 1] = 0x00;

		System.arraycopy(in, 0, temp, temp.length - in.length, in.length);

		BigInteger bi = new BigInteger(1, temp);
		BigInteger retval = bi.modPow(exponent, modulus);
		byte[] out = retval.toByteArray();

		// chop off extra zero from front if needed
		if (out.length > keysize) {
			byte[] b = new byte[keysize];
			System.arraycopy(out, out.length - keysize, b, 0, keysize);
			return b;
		} else {
			return out;
		}
	}

	private int readLengthFromBuf() {
		int len = certs[certsOffset++] & 0xff;
		if (len < 128) {
			return len;
		} else {
			len %= 128;
			int retval = 0;
			for (int i = 0; i < len; i++) {
				retval <<= 8;
				retval += certs[certsOffset++] & 0xff;
			}
			return retval;
		}
	}
}