package net.sourceforge.javacardsign.applet;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.RandomData;

public class PKIApplet extends Applet {
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new PKIApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	private PKIApplet() {
		randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	}

	private final static byte	INS_INIT_UPDATE	= (byte) 0x50;
	private final static byte	INS_EXT_AUTH	= (byte) 0x82;
	public final static byte	INS_STORE_DATA	= (byte) 0xE2;

	private boolean			isEnd	= false;
	private SecureChannel	secureChannel;
	private RandomData		randomData;

	public boolean select() {
		secureChannel = GPSystem.getSecureChannel();
		return true;
	}

	public void process(APDU apdu) {
		if (selectingApplet()) {
			return;
		}
		short	len		= 0;
		byte[]	buffer	= apdu.getBuffer();

		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_INIT_UPDATE:
		case INS_EXT_AUTH:
			if (isEnd)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, secureChannel.processSecurity(apdu));
			break;
		case INS_STORE_DATA:
			if (isEnd || secureChannel.getSecurityLevel() == SecureChannel.NO_SECURITY_LEVEL)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			len = apdu.setIncomingAndReceive();
			secureChannel.unwrap(buffer, (short) 0, (short) (5 + len));
			len = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
			// isEnd = true;
			break;
		case (byte) 0x84:
			randomData.generateData(buffer, ISO7816.OFFSET_CDATA, (short) (buffer[ISO7816.OFFSET_LC] & 0xFF));
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}

		if (len > 0) {
			apdu.setOutgoing();
			apdu.setOutgoingLength(len);
			apdu.sendBytesLong(buffer, ISO7816.OFFSET_CDATA, len);
		}
	}
}
