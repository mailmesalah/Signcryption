import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import org.bouncycastle.math.ec.ECPoint;

@XmlRootElement(name = "SigncryptedData")
public class SigncryptedData {
	public SigncryptedData() {

	}

	public SigncryptedData(String c, ECPoint T, BigInteger s,ECPoint publicKeyAlice) {
		this.c=c;
		this.T=T;
		this.s=s;
		this.publicKeyAlice=publicKeyAlice;
	}

	
	
	/*
	 *  Objecting Persisting Part
	 */
	@XmlElement(name = "c")
	public String c;
	@XmlElement(name = "T")
	public ECPoint T;
	@XmlElement(name = "s")
	public BigInteger s;
	@XmlElement(name = "PublicKeyAlice")
	public ECPoint publicKeyAlice;

	public static void marshal(SigncryptedData sd, OutputStream out)
			throws IOException {
		try {
			JAXBContext jc = JAXBContext.newInstance(SigncryptedData.class);
			Marshaller marshaller = jc.createMarshaller();
			marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			marshaller.marshal(sd, out);
		} catch (JAXBException ex) {
			throw new IOException(ex);
		} finally {
			out.close();
		}
	}

	public static SigncryptedData unmarshal(InputStream in) throws IOException {

		try {
			JAXBContext jc = JAXBContext.newInstance(SigncryptedData.class);
			Unmarshaller unmarshaller = jc.createUnmarshaller();

			return (SigncryptedData) unmarshaller.unmarshal(in);
		} catch (JAXBException ex) {
			throw new IOException(ex);
		} finally {
			in.close();
		}
	}

}
