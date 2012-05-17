package org.misty.rc.crypt;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class Blowfish {
	public static final String CRYPT_KEY = "it might as well be spring";
	public static final String TRANSFORMATION = "Blowfish";
	
	public static String encrypt(String key, String clearText) throws Exception {
		SecretKeySpec skspec = new SecretKeySpec(key.getBytes(), TRANSFORMATION);
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, skspec);
		byte[] encryptedBytes = cipher.doFinal(clearText.getBytes());
		
		return new String(Hex.encodeHex(encryptedBytes));
	}
	
	public static String decrypt(String key, String encryptedText) throws Exception{
		byte[] encryptedBytes = null;
		
		try {
			encryptedBytes = Hex.decodeHex(encryptedText.toCharArray());
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		SecretKeySpec skspec = new SecretKeySpec(key.getBytes(), TRANSFORMATION);
		Cipher cipher = Cipher.getInstance(TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, skspec);
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		
		return new String(decryptedBytes);
	}
}
