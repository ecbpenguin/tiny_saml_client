package com.ecbpenguin.saml.client.utils;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * This class uses the OpenSAML Deflate encoder to give us a much quicker, less error-proone
 * means to do a Deflate encoding for a SAML response rather than implementing the signatures ourselves
 * 
 * @author ecbpenguin
 *
 */
public class StringHTTPRedirectDeflateEncoder extends HTTPRedirectDeflateEncoder {

	private static final Logger LOGGER = LoggerFactory.getLogger(StringHTTPRedirectDeflateEncoder.class);

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
