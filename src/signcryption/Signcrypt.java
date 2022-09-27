package signcryption;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class Signcrypt extends AbstractSigncrypt {
	private ECPoint publicKeyReceiver;
	private BigInteger privateKeySender;
	private String message;
	private SigncryptPacket c;
	private BigInteger nounce;

	/**
	 * To signcrypt a message, the following parameters are necessary:
	 * 
	 * The private key of the sender, an BigInteger [1..q],<br>
	 * The public key of the receiver, a Point in the curve, <br>
	 * The message
	 * 
	 * @param privateKeySender
	 * @param publicKeyReceiver
	 * @param message
	 * @throws Exception 
	 */
	public Signcrypt(BigInteger privateKeySender, ECPoint publicKeyReceiver,
			String message, SigncryptionSettings settings,Fields f) throws Exception {
		super(settings);
		
		this.q=f.getQ();
		this.curve=f.getCurve();		
		this.G=f.getG();
		//new Fields(this, settings.ft);
		c = new SigncryptPacket();
		this.privateKeySender = privateKeySender;
		if (publicKeyReceiver != null)
			this.publicKeyReceiver = publicKeyReceiver;
		else { // For testing
			this.privateKeySender = privateKeySender.add(BigInteger.ONE);
			this.publicKeyReceiver = G.multiply(privateKeySender);
			//System.out.println(this.publicKeyReceiver);
		}
		
		this.message = message;
		setRandomNounce();
	}

	/***
	 * Calculate String c, ECPoint R and BigInteger s and wrap it into the class
	 * Cryptogram.
	 * 
	 * @return Cryptogram
	 */
	public SigncryptPacket getSignCryptPacket() {
		calculate();
		return c;
	}

	/**
	 * Calculate the matematics of the unsigncryption.
	 */
	private void calculate() {
		// Printing Bob's Public Key
		//System.out.println("Public Key Of Bob:");
		//System.out.println(publicKeyReceiver.getX().toBigInteger()+" "+publicKeyReceiver.getY().toBigInteger());
		
		c.settings = settings;
		
		//Step 3: Computes k1 = hash(vG).
		ECPoint tmp = G.multiply(nounce);
		K1 = SHA256asAbsBigInt(ConcatECPoints(tmp));
		System.out.println("Key K1 is "+K1);
		
		//Step 4: Computes (k2) = hash(vPb).
		K2 = SHA256asBytes(ConcatECPoints(publicKeyReceiver.multiply(nounce)));
		System.out.println("Key K2  (K2,K3 Previously)is "+ new BigInteger(K2));
		
		//Step 5: c = Ek2 (m)
		c.c = new Cryptogram(message, K2, settings);
		System.out.println("Encrypted Message is [ c ] "+new BigInteger(c.c.getEncrypted()));
		
		//Step 6: r = KHk3 (c || k1)
		r = SHA256asAbsBigInt(c.c + K1.toString());
		System.out.println("r is computed as "+r);
		
		//Step 7: Computes s = v / (r + va) mod q
		c.s = nounce.multiply(r.add(privateKeySender).modInverse(q)).mod(q);
		System.out.println("s is computed as "+c.s);
		
		//Step 8:  Compute R = rG.
		c.R = G.multiply(r);
		System.out.println("T is computed as "+c.R.getX().toBigInteger()+" "+c.R.getY().toBigInteger());
		// Compress R to the half R
		c.R = new ECPoint.Fp(c.R.getCurve(), c.R.getX(), c.R.getY(), true);
	}

	/**
	 * Makes a secure random nonce that belongs to [1..q-1]
	 */
	private void setRandomNounce() {
		do {
			nounce = secureRandomUniformBigInteger();
		} while (nounce.compareTo(q) > -1);// Ensure nounce < q
	}

	public String toString() {
		return "message:" + message + "\nnounce:" + nounce + "("
				+ nounce.bitLength() + ")";
	}
}