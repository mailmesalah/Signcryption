import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.*;

public class AESEncryptionDecryption {
	 private static final String Algorithm = "AES";
	 
	 public static String encrypt(String Data,byte[] keyValue) throws Exception {
	        Key key = generateKey(keyValue);
	        Cipher c = Cipher.getInstance(Algorithm);
	        c.init(Cipher.ENCRYPT_MODE, key);
	        byte[] encVal = c.doFinal(Data.getBytes());
	        String encryptedValue = new BASE64Encoder().encode(encVal);
	        return encryptedValue;
	    }

	    public static String decrypt(String encryptedData,byte[] keyValue) throws Exception {
	        Key key = generateKey(keyValue);
	        Cipher c = Cipher.getInstance(Algorithm);
	        c.init(Cipher.DECRYPT_MODE, key);
	        byte[] decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
	        byte[] decValue = c.doFinal(decordedValue);
	        String decryptedValue = new String(decValue);
	        return decryptedValue;
	    }
	    private static Key generateKey(byte[] keyValue) throws Exception {
	        Key key = new SecretKeySpec(keyValue, Algorithm);
	        return key;
	}
	    
	    public static void main(String arg[]){
	    	String k="1234567890123456";
	    	String k1="1123456789012345";
	    	String m="Hello";
	    	String es="";
	    	String ds="";
	    	try {
				es=encrypt(m, k.getBytes());
				ds=decrypt(es, k.getBytes());
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			System.out.println(es+ds);
	    	
	    }
}
