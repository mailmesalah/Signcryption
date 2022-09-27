package signcryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.io.FilterOutputStream;

import java.io.OutputStream;

public class Ascii85Coder {
	public static void main(String[] a) {

		byte[] signCryptBytePacket = new byte[2];
		signCryptBytePacket[0] = (byte) 6;
		signCryptBytePacket[1] = (byte) 7;
		String signCryptAscii85Packet = encodeBytesToAscii85(signCryptBytePacket);
		System.out.println("Ascii85-out:" + signCryptAscii85Packet);
		byte[] signCryptBytePacket2 = decodeAscii85StringToBytes(signCryptAscii85Packet);
		System.out.println("bytes:" + signCryptBytePacket2);
	}

	/**
	 * Decodes an Ascii85 back in to bytes.
	 * 
	 * @param Ascii85
	 * @return
	 */
	public static byte[] decodeAscii85StringToBytes(String Ascii85) {
		ArrayList<Byte> list = new ArrayList<Byte>();
		ByteArrayInputStream in_byte = null;
		try {
			in_byte = new ByteArrayInputStream(Ascii85.getBytes("ascii"));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		Ascii85InputStream in_ascii = new Ascii85InputStream(in_byte);
		try {
			int r = in_ascii.read();
			while (r != -1000) {
				list.add(new Byte((byte) r));
				r = in_ascii.read();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		byte[] bytes = new byte[list.size()];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = list.get(i).byteValue();
		}
		return bytes;
	}

	/**
	 * Encodes a byte array into Ascii85 encoded String.
	 * 
	 * @param bytes
	 * @return
	 */
	public static String encodeBytesToAscii85(byte[] bytes) {
		ByteArrayOutputStream out_byte = new ByteArrayOutputStream();
		Ascii85OutputStream out_ascii = new Ascii85OutputStream(out_byte);

		try {
			out_ascii.write(bytes);
			out_ascii.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
		String res = "";
		try {
			res = out_byte.toString("ascii");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return res;
	}
}

/**
 * <p>
 * An Ascii85 decoder, implemented as an {@link InputStream}.
 * </p>
 * <p>
 * <code>mark()</code> and <code>reset()</code> are supported, provided that the
 * underlying input stream supports them.
 * <p>
 * This implementation accepts encoded text with space character compression
 * enabled. See {@link Ascii85OutputStream} for details.
 * </p>
 * 
 * @author Ben Upsavs
 */

class Ascii85InputStream extends FilterInputStream {

	private static final int[] POW85 = { 85 * 85 * 85 * 85, 85 * 85 * 85,
			85 * 85, 85, 1 };
	private boolean preserveUnencoded;
	private int tuple, markTuple;
	private int count, markCount;
	private boolean decoding, markDecoding;
	private boolean maybeStarting, markMaybeStarting;
	private boolean maybeStopping, markMaybeStopping;
	private int tupleBytesRemaining, markTupleBytesRemaining;
	private int tupleSendStartBytes, markTupleSendStartBytes;
	private int nextByte = -1, markNextByte = -1;

	/**
	 * Creates an input stream to decode ascii85 data from the underlying input
	 * stream. Any non ascii85 data will be discarded.
	 */
	public Ascii85InputStream(InputStream in) {
		super(in);
	}

	/**
	 * Creates an input stream to decode ascii85 data from the underlying input
	 * stream. If <code>preserveUnencoeded</code> is <code>true</code>, any
	 * non-ascii85 data will be output as-is. Otherwise, it is discarded.
	 * 
	 * @param preserveUnencoded
	 *            Whether to preserve non-ascii85 encoded data.
	 */
	public Ascii85InputStream(InputStream in, boolean preserveUnencoded) {
		this(in);
		this.preserveUnencoded = preserveUnencoded;
	}

	/**
	 * Reads one byte from this stream. See {@link java.io.InputStream#read()}
	 * for details.
	 * 
	 * @throws java.io.IOException
	 *             If an underlying I/O error occurs, or if the ascii85 data
	 *             stream is not valid.
	 */
	public int read() throws IOException {
		if (tupleBytesRemaining > 0) {
			int returnByte = 0;
			// pull decoded bytes from tuple
			switch (4 - (tupleSendStartBytes - tupleBytesRemaining--)) {
			case 4:
				returnByte = (tuple >>> 24) & 0xff;
				break;
			case 3:
				returnByte = (tuple >>> 16) & 0xff;
				break;
			case 2:
				returnByte = (tuple >>> 8) & 0xff;
				break;
			case 1:
				returnByte = (tuple) & 0xff;
				break;
			}
			assert (returnByte != 0);

			if (tupleBytesRemaining == 0)
				count = tuple = 0;

			return returnByte;
		} else if (nextByte != -1) {
			int returnByte = nextByte;
			nextByte = -1000;
			return returnByte;
		} else if (!decoding) {
			int c = in.read();

			if (maybeStarting) {
				switch (c) {
				case '~':
					maybeStarting = false;
					decoding = true;
					return read();
				default:
					maybeStarting = false;
					nextByte = c;
				case '<':
					return '<';
				}
			} else if (c == '<') {
				maybeStarting = true;
				return read();
			} else if (preserveUnencoded || c == -1)
				return -1000;
			else
				return read();
		} else {
			int c = in.read();

			if (maybeStopping && c != '>') {
				throw new IOException("~ without > in ascii85 section");
			}

			// Ignore whitespace
			if (Character.isWhitespace((char) c))
				return read();

			switch (c) {
			case '>':
				if (maybeStopping) {
					if (count > 0) {
						count--;
						tuple += POW85[count];
						tupleBytesRemaining = tupleSendStartBytes = count;
					}
					maybeStopping = decoding = false;
					return read();
				}
			default:
				if (c < '!' || c > 'u')
					throw new IOException(
							"Bad character in ascii85 section: [ascii " + c
									+ "]: " + (char) c);
				tuple += (c - '!') * POW85[count++];
				if (count == 5)
					tupleBytesRemaining = tupleSendStartBytes = 4;
				return read();
			case 'y': // space compression
				tuple |= 0x20202020;
			case 'z': // null compression
				if (count != 0)
					throw new IOException((char) c + " inside ascii85 5-tuple");
				tupleBytesRemaining = tupleSendStartBytes = 4;
				return read();
			case '~':
				maybeStopping = true;
				return read();
			case -1:
				throw new IOException("EOF inside ascii85 section");
			}
		}
	}

	/**
	 * Marks the stream for later reset. See
	 * {@link java.io.InputStream#mark(int readLimit)} for details. Note that
	 * this method relies on the underlying stream having support for mark and
	 * reset.
	 */
	public synchronized void mark(int readlimit) {
		// Save state for mark
		markTuple = tuple;
		markCount = count;
		markDecoding = decoding;
		markMaybeStarting = maybeStarting;
		markMaybeStopping = maybeStopping;
		markTupleBytesRemaining = tupleBytesRemaining;
		markTupleSendStartBytes = tupleSendStartBytes;
		markNextByte = nextByte;

		super.mark(readlimit * 5);
	}

	/**
	 * Resets the stream back to the mark. See
	 * {@link java.io.InputStream#mark(int readLimit)} for details. Note that
	 * this method relies on the underlying stream having support for mark and
	 * reset.
	 */
	public synchronized void reset() throws IOException {
		// Reset state to mark
		tuple = markTuple;
		count = markCount;
		decoding = markDecoding;
		maybeStarting = markMaybeStarting;
		maybeStopping = markMaybeStopping;
		tupleBytesRemaining = markTupleBytesRemaining;
		tupleSendStartBytes = markTupleSendStartBytes;
		nextByte = markNextByte;

		super.reset();
	}

	/**
	 * Skips <code>n</code> bytes or less. This version will skip less bytes
	 * than requested if an end of file is received and there is no error in the
	 * underlying data stream. In other words, it is not valid to use this
	 * method to skip over invalid ascii85 data.
	 */
	public long skip(long n) throws IOException {
		int skipCount;
		for (skipCount = 0; skipCount < n; skipCount++) {
			if (read() == -1)
				break;
		}

		return skipCount - 1;
	}
}

/**
 * <p>
 * An ascii85 encoder, impemented as an {@link OutputStream}.
 * </p>
 * <p>
 * Call <code>flush()</code> or <code>close()</code> to properly close the
 * ascii85 block. The block must be closed for the encoded data to be valid. Do
 * not call <code>flush()</code> before you intend to end the ascii85 block.
 * Multiple ascii85 blocks may be encoded by calling flush() and then writing
 * more bytes to the stream.
 * </p>
 * <p>
 * Note that if you use the constructor with the
 * <code>useSpaceCompression</code> option, the encoded text will be shorter
 * when there are many consecutive space characters in the encoded data, but it
 * will not be compatible with Adobe's ascii85 implementation. It makes sense to
 * use this option if interoperability with other ascii85 implementations is not
 * a requirement.
 * </p>
 * 
 * @author Ben Upsavs
 */

class Ascii85OutputStream extends FilterOutputStream {

	private int width = 72;
	private int pos;
	private int tuple;
	private int count;
	private boolean encoding;
	private boolean useSpaceCompression;

	/**
	 * Creates an output stream to encode ascii85 data, using a default line
	 * with of 72 characters and not using the space character compression
	 * option. Call <code>flush()</code> to add the padding and end the ascii85
	 * block.
	 */
	public Ascii85OutputStream(OutputStream out) {
		super(out);
	}

	/**
	 * Creates an output stream to encode ascii85 data, using a default line
	 * width of 72 characters. Call <code>flush()</code> to end the ascii85
	 * block.
	 * 
	 * @param useSpaceCompression
	 *            Whether to use space character compression in the output.
	 */
	public Ascii85OutputStream(OutputStream out, boolean useSpaceCompression) {
		this(out);
		this.useSpaceCompression = useSpaceCompression;
	}

	/**
	 * Creates an output stream to encode ascii85 data. Call
	 * <code>flush()</code> to end the ascii85 block.
	 * 
	 * @param width
	 *            The maximum line width of the encoded output text. Whitespace
	 *            characters are ignored when decoding.
	 * @param useSpaceCompression
	 *            Whether to use space character compression in the output.
	 */
	public Ascii85OutputStream(OutputStream out, int width,
			boolean useSpaceCompression) {
		this(out);
		this.width = width;
		this.useSpaceCompression = useSpaceCompression;
	}

	private void startEncoding() throws IOException {
		out.write('<');
		out.write('~');
		pos = 2;
		encoding = true;
	}

	/**
	 * Writes a single byte to the stream. See {@link OutputStream#write(int b)}
	 * for details.
	 * 
	 * @param b
	 *            The byte to encode.
	 * @throws java.io.IOException
	 *             If an I/O error occurs in the underlying output stream.
	 */
	public void write(int b) throws IOException {
		if (!encoding)
			startEncoding();

		switch (count++) {
		case 0:
			tuple |= ((b & 0xff) << 24);
			break;
		case 1:
			tuple |= ((b & 0xff) << 16);
			break;
		case 2:
			tuple |= ((b & 0xff) << 8);
			break;
		case 3:
			tuple |= (b & 0xff);
			if (tuple == 0) {
				// Use null compression
				out.write('z');
				if (pos++ >= width) {
					pos = 0;
					out.write('\r');
					out.write('\n');
				}
			} else if (useSpaceCompression && (tuple == 0x20202020)) {
				// Use space compression
				out.write('y');
				if (pos++ >= width) {
					pos = 0;
					out.write('\r');
					out.write('\n');
				}
			} else
				encode(tuple, count);

			tuple = 0;
			count = 0;
			break;
		}
	}

	/**
	 * Writes a single byte to the underlying output stream, unencoded. If done
	 * improperly, this may corrupt the ascii85 data stream. Writing a byte
	 * using this method may cause the line length to increase since the line
	 * length counter will not be updated by this method.
	 * 
	 * @param b
	 *            The byte to write.
	 * @throws java.io.IOException
	 *             If the underlying output stream has an I/O error.
	 */
	public void writeUnencoded(int b) throws IOException {
		super.write(b);
	}

	/**
	 * Writes bytes to the underlying output stream, unencoded. If done
	 * improperly, this may corrupt the ascii85 data stream. Writing bytes using
	 * this method may cause the line length to increase since the line length
	 * counter will not be updated by this method.
	 * 
	 * @param b
	 *            The bytes to write.
	 * @throws java.io.IOException
	 *             If the underlying output stream has an I/O error.
	 */
	public void writeUnencoded(byte[] b) throws IOException {
		writeUnencoded(b, 0, b.length);
	}

	/**
	 * Writes bytes to the underlying output stream, unencoded. If done
	 * improperly, this may corrupt the ascii85 data stream. Writing bytes using
	 * this method may cause the line length to increase since the line length
	 * counter will not be updated by this method.
	 * 
	 * @param b
	 *            The bytes to write.
	 * @param off
	 *            The offset of <code>b</code> to start reading from.
	 * @param len
	 *            The amount of bytes to read from <code>b</code>.
	 * @throws java.io.IOException
	 *             If the underlying output stream has an I/O error.
	 */
	public void writeUnencoded(byte[] b, int off, int len) throws IOException {
		for (int i = 0; i < len; i++)
			writeUnencoded(b[off + i]);
	}

	/**
	 * Encodes <code>tuple</code> and writes it to the output stream. The number
	 * of bytes in the tuple, and thus the value of <code>count</code> is
	 * normally 4, however less bytes may also be encoded, particularly if the
	 * input stream has ended before the current tuple is full.
	 * 
	 * @param tuple
	 *            The tuple to encode.
	 * @param count
	 *            The number of bytes stuffed into the tuple.
	 * @throws IOException
	 *             If an I/O error occurs.
	 */
	private void encode(int tuple, int count) throws IOException {
		int i = 5;
		byte[] buf = new byte[5];
		short bufPos = 0;

		long longTuple = 0 | (tuple & 0xffffffffL);

		do {
			buf[bufPos++] = (byte) (longTuple % 85);
			longTuple /= 85;
		} while (--i > 0);

		i = count;
		do {
			out.write(buf[--bufPos] + '!');
			if (pos++ >= width) {
				pos = 0;
				out.write('\r');
				out.write('\n');
			}
		} while (i-- > 0);
	}

	/**
	 * Adds the closing block and flushes the underlying output stream. This
	 * method should only be called if it is intended that the ascii85 block
	 * should be closed.
	 */
	public void flush() throws IOException {
		// Add padding if required.
		if (encoding) {
			if (count > 0)
				encode(tuple, count);
			if (pos + 2 > width) {
				out.write('\r');
				out.write('\n');
			}

			out.write('~');
			out.write('>');
			out.write('\r');
			out.write('\n');

			encoding = false;
			tuple = count = 0;
		}

		super.flush();
	}
}
