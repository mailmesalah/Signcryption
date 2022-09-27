import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

public class Signcryption {

	/**
	 * @param args
	 */
	private static FileInputStream inStream;
	private static FileOutputStream outStream;

	/*
	 * Parameters Public to all
	 */
	private static ECCurve curve;
	private static BigInteger q;
	private static ECPoint G;
	private static BigInteger a;
	private static BigInteger b;

	private static void initialiseParameters() throws Exception {
		/*
		 * Setting the Initial parameters
		 */

		/*
		 * Setting a of the curve equation
		 */
		System.out
				.println("Enter A of the Curve satisfying (4a^3 + 27b^2  mod q  ≠ 0) : ");
		String read = new BufferedReader(new InputStreamReader(System.in))
				.readLine();
		a = new BigInteger(read);

		/*
		 * Setting a of the curve equation
		 */
		System.out
				.println("Enter B of the Curve satisfying (4a^3 + 27b^2  mod q  ≠ 0) : ");
		read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		b = new BigInteger(read);

		/*
		 * Setting Value of q the prime number
		 */
		q = new BigInteger("211");// q, The prime

		/*
		 * Curve object is created using q, a and b
		 */
		curve = new ECCurve.Fp(q, a, b);

		/*
		 * Set the base point G
		 */
		BigInteger x = new BigInteger("2");
		BigInteger y = new BigInteger("2");
		G = new ECPoint.Fp(curve, new ECFieldElement.Fp(q, x),
				new ECFieldElement.Fp(q, y));
	}

	private static SigncryptedData getSigncryptedData(String message) throws Exception {

		/*
		 * Generating Bob's Public Key using user inputs
		 */
		System.out.println("Enter Bob's Public Key : ");
		System.out.println("x : ");
		String read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		BigInteger Bx= new BigInteger(read);
		System.out.println("Enter Bob's Public Key : ");			
		read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		BigInteger By= new BigInteger(read);
		
		ECPoint publicKeyBob = new ECPoint.Fp(curve, new ECFieldElement.Fp(q, Bx),new ECFieldElement.Fp(q, By));;
		
		/*
		 * Generating Alice's Random Private Key and its Public Key 
		 */
		BigInteger privateKeyAlice = new BigInteger(256, new SecureRandom());
		ECPoint publicKeyAlice = G.multiply(privateKeyAlice);
		

		/*
		 * Step 2: Randomly selects an integer v, where v ≤ n - 1
		 */
		BigInteger v;
		do {
			v = new BigInteger(q.bitLength(), new SecureRandom());
		} while (v.compareTo(q) > -1);// Ensure v < q
		System.out.println("v=" + v);
		v=new BigInteger("210");
		/**************************************************************/

		/*
		 * Step 3: Computes k1 = hash(vG).
		 */
		ECPoint vG = G.multiply(v);
		System.out.println("vG=" + vG.getX() + " " + vG.getY());
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update((vG.getX().toString() + vG.getY().toString()).getBytes());
		BigInteger K1 = new BigInteger(md.digest());
		System.out.println("K1=" + K1);
		/**************************************************************/

		/*
		 * Step 4: Computes (k2, k3) = hash(vPb).
		 */
		ECPoint vPb = publicKeyBob.multiply(v);
		System.out.println("vPb=" + vPb.getX() + " " + vPb.getY());
		md.update((vPb.getX().toString() + vPb.getY().toString()).getBytes());
		byte[] hash = md.digest();

		byte[] K2 = new byte[(hash.length / 2)];
		System.arraycopy(hash, 0, K2, 0, (hash.length / 2));

		byte[] K3 = new byte[(hash.length / 2)];
		System.arraycopy(hash, (hash.length / 2), K3, 0, (hash.length / 2));
		/**************************************************************/
		System.out.println("k2,k3=" + K2 + " " + K3);
		/*
		 * Step 5:Uses the symmetric encryption algorithm to generate cipher c =
		 * Ek2 (m)
		 */

		String c = AESEncryptionDecryption.encrypt(message, K2);
		/**************************************************************/
		System.out.println("c=" + c);
		/*
		 * Step 6: Uses one-way keyed hash function to generate: r = KHk3 (c ||
		 * k1 || IDA || IDB)
		 */
		//+ IDa + IDb
		byte[] rByte = KeyedHashing.getHashCode(K2, (c + K1 ));
		
		BigInteger r = new BigInteger(rByte);
		System.out.println("r=" + r);
		/**************************************************************/

		/*
		 * Step 7: Computes s = v / (r + va) mod q
		 */
		BigInteger s = v.multiply(r.add(privateKeyAlice).modInverse(q)).mod(q);
		//v.divide((r.add(privateKeyAlice).mod(q)));
		
		System.out.println("s=" + s);
		/**************************************************************/

		/*
		 * Step 8: Compute T = rG.
		 */
		ECPoint T = G.multiply(r);
		System.out.println("T=" + T.getX() + " " + T.getY());
		/**************************************************************/

		/*
		 * Step 9: Sends the signcrypted text (c, T, s) to Bob.
		 */
		System.out.println("T" + T + " c" + c + " s" + s);
		return new SigncryptedData(c, T, s,publicKeyAlice);
		/**************************************************************/
	}

	private static String getUnsigncryptedData(SigncryptedData sd) throws Exception {

		/*
		 * Generating Bob's Private Key using user input
		 */
		System.out.println("Enter Bob's Private Key : ");
		String read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		
		BigInteger privateKeyBob = new BigInteger(read);
		
		/*
		 * Retrieving Alice's Public Key from the Signcrypted Data
		 */
		ECPoint publicKeyAlice=sd.publicKeyAlice;
				
		/*
		 * Step 2: Computes k1 = hash(sT + sPa).
		 */
		ECPoint sT = sd.T.multiply(sd.s);
		System.out.println("sT=" + sT.getX() + " " + sT.getY());
		ECPoint sPa = publicKeyAlice.multiply(sd.s);
		System.out.println("sPa=" + sPa.getX() + " " + sPa.getY());

		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update((sT.getX().toString() + sT.getY().toString() + sPa.getX() + sPa
				.getY()).getBytes());

		byte[] K1 = md.digest();
		System.out.println("K=" + K1);
		/**************************************************************/

		/*
		 * Step 3: Computes (k2, k3) = hash(vbsT + vbsPa).
		 */		
		ECPoint vbsT = sT.multiply(privateKeyBob);
		ECPoint vbsPa = sPa.multiply(privateKeyBob);
		
		md.update((vbsT.getX().toString() + vbsT.getY().toString()
				+ vbsPa.getX().toString() + vbsPa.getY().toString()).getBytes());
		System.out.println("vbsT + vbsPa=" + vbsT.getX() + " " + vbsT.getY()
				+ " " + vbsPa.getX() + " " + vbsPa.getY());
		byte[] hash = md.digest();

		byte[] K2 = new byte[(hash.length / 2)];
		System.arraycopy(hash, 0, K2, 0, (hash.length / 2));

		byte[] K3 = new byte[(hash.length / 2)];
		System.arraycopy(hash, (hash.length / 2), K3, 0, (hash.length / 2));
		/**************************************************************/
		System.out.println("k2,k3= " + K2 + " " + K3);
		System.out.println("hash=" + hash);
		/*
		 * Step 4: Uses the one-way keyed hash function to generate r = KHk3 (c
		 * || k1 || IDA || IDB)
		 */
		//+ IDa + IDb
		byte[] rByte = KeyedHashing.getHashCode(K3, (sd.c + K1 ));

		BigInteger r = new BigInteger(rByte);
		System.out.println("r=" + r);
		/**************************************************************/

		/*
		 * Step 5: Uses a symmetric decryption algorithm to generate plain text
		 * m = Dk2 (c)
		 */
		String message = "";
		try {
			message = AESEncryptionDecryption.decrypt(sd.c, K2);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		System.out.println(message);
		/**************************************************************/

		/*
		 * Step 6: Bob accepts the message 'm' only when rG = T .Otherwise he
		 * rejects.
		 */
		ECPoint rG = G.multiply(r);
		System.out.println("rG=" + rG.getX() + " " + rG.getY());
		if (rG.equals(sd.T)) {
			System.out.println("Message Is Accepted !");
			System.out.println("Message : " + message);

		} else {
			System.out.println("Message Is Not Accepted !");
			System.out.println("Message : " + message);
		}
		/**************************************************************/
		return message;
	}

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		initialiseParameters();

		System.out.println("Enter The Message : ");
		String read = new BufferedReader(new InputStreamReader(System.in))
				.readLine();

		SigncryptedData sd = getSigncryptedData(read);
		String message = getUnsigncryptedData(sd);
		/*
		 * if(args.length==2){ if(args[0].equals("Encrypt")){ /* Creating the
		 * output file to store the Signcrypted data
		 */
		// try {
		// outStream = new FileOutputStream(args[1]);
		// } catch (FileNotFoundException e) {
		// TODO Auto-generated catch block
		// e.printStackTrace();
		// }

		/*
		 * Creating Signcrypted data
		 */
		// SigncryptedData sd= getSigncryptedData("helloooooo");

		/*
		 * Saving SigncryptedData
		 */
		// try {
		// SigncryptedData.marshal(sd,outStream);
		// } catch (IOException e) {
		// TODO Auto-generated catch block
		// e.printStackTrace();
		// }
		// }else if(args[0].equals("Decrypt")){
		/*
		 * Creating input file to read the stored Signcrypted data
		 */
		// try {
		// inStream = new FileInputStream(args[1]);
		// } catch (FileNotFoundException e) {
		// TODO Auto-generated catch block
		// e.printStackTrace();
		// }

		// SigncryptedData sd=new SigncryptedData();
		// try {
		// sd=SigncryptedData.unmarshal(inStream);
		// } catch (IOException e) {
		// TODO Auto-generated catch block
		// e.printStackTrace();
		// }

		/*
		 * Decrypt data from Signcrypted data
		 */
		// String message=getUnsigncryptedData(sd);

		/*
		 * Print the data
		 */
		// System.out.println(message);
		// }else{
		// System.out.println("Invalid Options !");
		// }
		// }else{
		// System.out.println("Invalid Arguments !");
		// }
	}

}
