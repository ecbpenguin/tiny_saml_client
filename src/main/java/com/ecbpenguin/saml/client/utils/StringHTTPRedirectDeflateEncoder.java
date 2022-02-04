package com.ecbpenguin.saml.client.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
/**
 * This class uses the OpenSAML Deflate encoder to give us a much quicker, less error-proone
 * means to do a Deflate encoding for a SAML response rather than implementing the signatures ourselves
 * 
 * @author ecbpenguin
 *
 */
public class StringHTTPRedirectDeflateEncoder extends HTTPRedirectDeflateEncoder {

	private static final Logger LOGGER = LoggerFactory.getLogger(StringHTTPRedirectDeflateEncoder.class);

	protected String deflateAndBase64Encode(final SAMLObject message) throws MessageEncodingException {
		LOGGER.debug("Deflating and Base64 encoding SAML message");
		final ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
		final DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, new Deflater(Deflater.DEFLATED, true));
		try {
			final String messageStr = SerializeSupport.nodeToString(marshallMessage(message));

			deflaterStream.write(messageStr.getBytes("UTF-8"));
			deflaterStream.finish();

			final String deflatedEncoded = Base64.getEncoder().withoutPadding().encodeToString(bytesOut.toByteArray());
			return deflatedEncoded;
		} catch (final IOException e) {
			throw new MessageEncodingException("Unable to DEFLATE and Base64 encode SAML message", e);
		} finally {
			if (bytesOut != null) {
				try {
					bytesOut.close();
				} catch (final IOException e) {
					LOGGER.warn("Unable to close output stream. Possible memory leak", e);
				}
			}
			if (deflaterStream != null) {
				try {
					deflaterStream.close();
				} catch (final IOException e) {
					LOGGER.warn("Unable to close deflater stream. Possible memory leak", e);
				}
			}
		}
	}
	/**
	 * This 
	 * @return
	 * @throws MessageEncodingException
	 */
	public final String createEncodedRequest() throws MessageEncodingException {
		final MessageContext<SAMLObject> messageContext = getMessageContext();
		final SAMLObject outboundMessage = messageContext.getMessage();
		final String endpointURL = getEndpointURL(messageContext).toString();

		removeSignature(outboundMessage);

		final String encodedMessage = deflateAndBase64Encode(outboundMessage);
		final String redirectUrl = buildRedirectURL(messageContext, endpointURL, encodedMessage);

		LOGGER.info("Returning redirect URL {}", redirectUrl);
		return redirectUrl;
	}

}
