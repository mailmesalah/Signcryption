package signcryption;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Serves unsigncryption process based on Elliptic Curve.
 * 
 * @author Jo Mehmet
 * 
 */
public class Unsigncrypt extends AbstractSigncrypt {
	private SigncryptPacket c;// From sender: c, R and s
	private ECPoint publicKeySender;
	private BigInteger privateKeyReceiver;

	/**
	 * Starts the unsigncryption process and gives access to the cleartext
	 * message, and its validity.
	 * 
	 * 
	 * @param privateKeySender
	 * @param privateKeyReceiver
	 * @param signCryptPacket
	 * @param settings
	 * @throws Exception 
	 */
	public Unsigncrypt(ECPoint publicKeySender, BigInteger privateKeyReceiver,
			byte[] signCryptPacket, SigncryptionSettings settings,Fields f) throws Exception {
		super(settings);
		
		this.q=f.getQ();
		this.curve=f.getCurve();		
		this.G=f.getG();
		//new Fields(this, settings.ft);
		this.c = new SigncryptPacket(signCryptPacket, settings, curve);
		if (publicKeySender != null)
			this.publicKeySender = publicKeySender;
		else { // For testing
			this.publicKeySender = G.multiply(privateKeyReceiver
					.add(BigInteger.ONE));
		}
		this.privateKeyReceiver = privateKeyReceiver;
		calculateSecrets();
	}

	/**
	 * Calculate K1, K2 and r
	 */
	private void calculateSecrets() {
		//System.out.println("Private Key Of Bob:");
		//System.out.println(privateKeyReceiver);
		
		//System.out.println("Public Key Of Alice:");
		//System.out.println(publicKeySender.getX().toBigInteger()+" "+publicKeySender.getY().toBigInteger());
		
		//Step 2:  Computes k1  =  hash(sT + sPa) or P=(R+Pa)*s 
		ECPoint P = c.R.add(publicKeySender).multiply(c.s);
		// K1 = hash(s(R + Pa))
		K1 = SHA256asAbsBigInt(ConcatECPoints(P));
		System.out.println("Key K1 is "+K1);
		
		//Step 3:  Computes (k2, k3) = hash(vbsT + vbsPa).
		P = P.multiply(privateKeyReceiver);
		// K2 = hash(v_b*s(R + Pa)
		K2 = SHA256asBytes(ConcatECPoints(P));
		System.out.println("Key K2(K2,K3 Previously) is "+new BigInteger(K2));
		c.c.setKey(K2);
		// r = hash(c , K1)
		r = SHA256asAbsBigInt(c.c + K2.toString());
		//System.out.println("rG "+r);
	}

	/**
	 * UTF-8 formated string of the message.
	 * 
	 * @return
	 */
	public String getStringMessage() {
		return c.c.getCleartextAsUTF8String();
	}

	/**
	 * The Unix timestamp of when the message was signcrypted in seconds.
	 * 
	 * @return
	 */
	public long getUnixTimeStamp() {
		return c.getTimeStamp();
	}

	/**
	 * Validate the integrity of the message.
	 * 
	 * @return boolean
	 */
	public boolean isAccepted() {
		return G.multiply(r).equals(c.R);
	}
}