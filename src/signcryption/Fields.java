package signcryption;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
/**
 * This class defines different Elliptic Curve fields and set the FieldType
 * chosen to an AbstractSigncrypt object.
 * 
 * To add more Elliptic Curve fields, extend this class.
 * 
 * @author Jo Mehmet
 * 
 */
public class Fields {
	private AbstractSigncrypt as;
	
	protected ECCurve curve;
	protected BigInteger q;
	protected ECPoint G;

	protected Fields(FieldType ft) throws Exception {		
		switch (ft) {
		case selfDefined:
			selfDefined();
			return;
		case P192:
			setP192();
			break;
		case P256:
			setP256();
			break;
		case P384:
			setP384();
			break;
		default:
			setP384();
			break;
		}
	}
	
	protected Fields(AbstractSigncrypt as, FieldType ft) throws Exception {
		this.as = as;
		switch (ft) {
		case selfDefined:
			selfDefined();
			return;
		case P192:
			setP192();
			break;
		case P256:
			setP256();
			break;
		case P384:
			setP384();
			break;
		default:
			setP384();
			break;
		}
	}

	private void setP192() {
		// p = 2^192 - 2^64 - 1
		BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF"
				+ "FFFFFFFEFFFFFFFFFFFFFFFF");
		System.out.println("p "+p);
		BigInteger a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF"
				+ "FFFFFFFEFFFFFFFFFFFFFFFC");
		System.out.println("a "+a);
		BigInteger b = fromHex("64210519E59C80E70FA7E9AB"
				+ "72243049FEB8DEECC146B9B1");
		System.out.println("b "+b);
		q = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF" + "99DEF836146BC9B1B4D22831");

		System.out.println("q "+q);
		curve = new ECCurve.Fp(p, a, b);
		G = curve.decodePoint(Hex.decode("04188DA80EB03090F"
				+ "67CBF20EB43A18800F4F" + "F0AFD82FF101207192B9"
				+ "5FFC8DA78631011ED6B2" + "4CDD573F977A11E794811"));
		System.out.println("G "+G.getX().toBigInteger()+" "+G.getY().toBigInteger());
	}

	private void setP256() {
		// p = 2^224 (2^32 - 1) + 2^192 + 2^96 - 1
		BigInteger p = fromHex("FFFFFFFF0000000100000000"
				+ "0000000000000000FFFFFFFF" + "FFFFFFFFFFFFFFFF");
		System.out.println("p "+p);
		BigInteger a = fromHex("FFFFFFFF0000000100000000"
				+ "0000000000000000FFFFFFFF" + "FFFFFFFFFFFFFFFC");
		System.out.println("a "+a);
		BigInteger b = fromHex("5AC635D8AA3A93E7B3EBBD55"
				+ "769886BC651D06B0CC53B0F6" + "3BCE3C3E27D2604B");
		System.out.println("b "+b);
		q = fromHex("FFFFFFFF00000000FFFFFFFF" + "FFFFFFFFBCE6FAADA7179E84"
				+ "F3B9CAC2FC632551");
		System.out.println("q "+q);
		curve = new ECCurve.Fp(p, a, b);
		G = curve.decodePoint(Hex.decode("046B17D1F2E12C424"
				+ "7F8BCE6E563A440F2770" + "37D812DEB33A0F4A1394"
				+ "5D898C2964FE342E2FE1" + "A7F9B8EE7EB4A7C0F9E1"
				+ "62BCE33576B315ECECBB" + "6406837BF51F5"));
		System.out.println("G "+G.getX().toBigInteger()+" "+G.getY().toBigInteger());
	}

	private void setP384() {
		// p = 2^384 - 2^128 - 2^96 + 2^32 - 1
		BigInteger p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF"
				+ "FFFFFFFFFFFFFFFFFFFFFFFF" + "FFFFFFFFFFFFFFFEFFFFFFFF"
				+ "0000000000000000FFFFFFFF");
		System.out.println("p "+p);
		BigInteger a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF"
				+ "FFFFFFFFFFFFFFFFFFFFFFFF" + "FFFFFFFFFFFFFFFEFFFFFFFF"
				+ "0000000000000000FFFFFFFC");
		System.out.println("a "+a);
		BigInteger b = fromHex("B3312FA7E23EE7E4988E056B"
				+ "E3F82D19181D9C6EFE814112" + "0314088F5013875AC656398D"
				+ "8A2ED19D2A85C8EDD3EC2AEF");
		System.out.println("b "+b);
		q = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF" + "FFFFFFFFFFFFFFFFFFFFFFFF"
				+ "C7634D81F4372DDF581A0DB2" + "48B0A77AECEC196ACCC52973");
		System.out.println("q "+q);
		curve = new ECCurve.Fp(p, a, b);
		G = curve.decodePoint(Hex.decode("04AA87CA22BE8B053"
				+ "78EB1C71EF320AD746E1" + "D3B628BA79B9859F741E"
				+ "082542A385502F25DBF5" + "5296C3A545E3872760AB"
				+ "73617DE4A96262C6F5D9" + "E98BF9292DC29F8F41DB"
				+ "D289A147CE9DA3113B5F" + "0B8C00A60B1CE1D7E819"
				+ "D7A431D7C90EA0E5F"));
		System.out.println("G "+G.getX().toBigInteger()+" "+G.getY().toBigInteger());
	}

	/**
	 * Initialize the field with the basepoint G. Values from the IS book p310.
	 * @throws Exception 
	 */
	protected void selfDefined() throws Exception {
		
		System.out.println("Please Enter the Prime number P:");
		String read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		BigInteger P = new BigInteger(read);
		//BigInteger P = new BigInteger("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319");// P, The prime
		
		System.out.println("Please Enter the Prime number Q:");
		read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		BigInteger Q = new BigInteger(read);
		//BigInteger Q = new BigInteger("39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643");// Q, The prime
		q=Q;
		
		System.out.println("Please Enter a of (4a^3 + 27b^2  mod q  ≠ 0):");
		read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		BigInteger a = new BigInteger(read);
		//BigInteger a = new BigInteger("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112316");// A
		
		System.out.println("Please Enter b of (4a^3 + 27b^2  mod q  ≠ 0):");
		read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		BigInteger b = new BigInteger(read);
		//BigInteger b = new BigInteger("27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575");// B
		
		curve = new ECCurve.Fp(P, a, b);
		/*
		 *  Set the base point G
		 */
		System.out.println("Please Enter x for Point G:");
		read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		BigInteger x = new BigInteger(read);
		//BigInteger x = new BigInteger("26247035095799689268623156744566981891852923491109213387815615900925518854738050089022388053975719786650872476732087");
		
		System.out.println("Please Enter y for Point G:");
		read = new BufferedReader(new InputStreamReader(System.in)).readLine();
		//BigInteger y = new BigInteger("8325710961489029985546751289520108179287853048861315594709205902480503199884419224438643760392947333078086511627871");
		BigInteger y = new BigInteger(read);
		G = new ECPoint.Fp(curve, new ECFieldElement.Fp(P, x),
				new ECFieldElement.Fp(P, y));
		
	}
	
	public BigInteger getQ(){
		return q;
	}
	
	public ECCurve getCurve(){
		return curve;
	}
	
	public ECPoint getG(){
		return G;
	}

	private static BigInteger fromHex(String hex) {
		return new BigInteger(1, Hex.decode(hex));
	}
}