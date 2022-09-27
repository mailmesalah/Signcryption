package signcryption;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Run {
	public static String message ;

	public static void main(String[] args) throws Exception {
		// PrivateKeySender
		
		System.out.println("Enter the message to Signcrypt  [ m ]:   ");
		message = new BufferedReader(new InputStreamReader(System.in)).readLine();
		
		//Private Key of Alice
		BigInteger v_a = new BigInteger(384, new SecureRandom());
		//Private Key of Bob
		BigInteger v_b = v_a;// PrivateKeyReceiver
		
		//System.out.println(v_a);
		
		//Settings for the Curve
		SigncryptionSettings settings = new SigncryptionSettings((byte) 0xAA,
				(byte) 0x01, FieldType.selfDefined, KeyLength.key256);
		
		Fields f = new Fields(FieldType.selfDefined);
		
		System.out.println("SIGNCRYPTION");
		Signcrypt sc = new Signcrypt(v_a, null, message, settings,f);		
		SigncryptPacket signcryptPacket = sc.getSignCryptPacket();

		//Encodes Signcrypted Data
		byte[] signCryptBytePacket = signcryptPacket.getPacketAsBytes();
		String stringpacket = Ascii85Coder
				.encodeBytesToAscii85(signCryptBytePacket);
		//System.out.println("Encoded Signcrypted Data: "+stringpacket);
		
		//Decodes Signcrypted Data
		signCryptBytePacket = Ascii85Coder
				.decodeAscii85StringToBytes(stringpacket);
		//System.out.println("Decoded Signcrypted Data: "+signCryptBytePacket);
		System.out.println("UNSIGNCRYPTION");
		Unsigncrypt us = new Unsigncrypt(null, v_b, signCryptBytePacket,
				settings,f);
		System.out.println("Decrypted Message is [ m ] " + us.getStringMessage());
		System.out.println("Successful Termination");

	}

	public void test(String message) {

		// Testparameters
			
	}
}