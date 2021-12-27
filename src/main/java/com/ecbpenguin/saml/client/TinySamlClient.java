package com.ecbpenguin.saml.client;

import java.io.IOException;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ecbpenguin.saml.client.utils.AuthnRequestUtils;
import com.ecbpenguin.saml.client.utils.SAMLResponseUtils;
import com.ecbpenguin.saml.client.utils.ServiceProviderMetadataUtils;
import com.ecbpenguin.saml.config.TinySamlClientConfig;

/**
 * This 
 * @author ecb_penguin
 *
 */
public class TinySamlClient {

	private static final Logger LOGGER = LoggerFactory.getLogger(TinySamlClient.class);
	
	private final AuthnRequestUtils authnRequestUtils;

	private final SAMLResponseUtils samlResponseUtils;

	private final ServiceProviderMetadataUtils serviceProviderMetadataUtils;

	public TinySamlClient() {
		this(null);
	}
	
	public TinySamlClient(final TinySamlClientConfig config) {

		try {
			InitializationService.initialize();
		} catch (final InitializationException e) {
			LOGGER.error("Failed to initialize OpenSAML", e);
			throw new RuntimeException(e);
		}

		final String spMetadataFile = config.getServiceProviderMetadataFile();
		serviceProviderMetadataUtils = new ServiceProviderMetadataUtils(spMetadataFile);
		authnRequestUtils = new AuthnRequestUtils(serviceProviderMetadataUtils);
		samlResponseUtils = new SAMLResponseUtils(config, serviceProviderMetadataUtils);

	}

	public final String buildSAMLRequest(final boolean sign) {
		AuthnRequest request = authnRequestUtils.buildAuthnRequest(sign);
		return AuthnRequestUtils.wireEncodeAuthRequest(request);
	}


	/**
	 * Returns the name ID associated with the SAML response, or null if the name ID can
	 * @param encodedSamlResponse the base64 encoded SAML response from the POST binding
	 * 
	 * @return the name in the response, null otherwise.
	 */
	public final String parseSAMLResponsePostBinding(final String encodedSamlResponse) {
		try {
			return samlResponseUtils.validateSAMLResponsePostBinding(encodedSamlResponse);
		} catch (final IOException e) {
			System.out.println("Could not validate SAML response " + e.getMessage());
			LOGGER.error("Could not process SAML Response: ", e);
			return null;
		}
	}
}
