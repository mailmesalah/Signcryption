import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyedHashing {

	public static byte[] getHashCode(byte[] secretByte, String macData)
			throws NoSuchAlgorithmException, KeyManagementException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {

		Mac mac = Mac.getInstance("HmacSHA256");
		// get the bytes of the hmac key and data string
		//byte[] secretByte = macKey.getBytes("UTF-8");
		byte[] dataBytes = macData.getBytes("UTF-8");
		SecretKey secret = new SecretKeySpec(secretByte, "HMACSHA256");

		mac.init(secret);
		return mac.doFinal(dataBytes);
		

	}
}