package com.ecbpenguin.saml.client;

import java.io.IOException;

import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ecbpenguin.saml.client.utils.AuthnRequestUtils;
import com.ecbpenguin.saml.client.utils.IdpMetadataUtils;
import com.ecbpenguin.saml.client.utils.SAMLResponseUtils;
import com.ecbpenguin.saml.client.utils.ServiceProviderMetadataUtils;
import com.ecbpenguin.saml.config.TinySamlClientConfig;
import com.ecbpenguin.utils.FileLogUtils;

/**
 * This is a simple SAML client that is "operational" - e.g. resilient to metadata / certificate changes
 * @author ecb_penguin
 *
 */
public class TinySamlClient {

	private final Logger LOGGER = LoggerFactory.getLogger(TinySamlClient.class);

	private final AuthnRequestUtils authnRequestUtils;

	private final SAMLResponseUtils samlResponseUtils;

	private final IdpMetadataUtils idpMetadataUtils; 

	private final ServiceProviderMetadataUtils serviceProviderMetadataUtils;

	public TinySamlClient() throws IOException {
		this(null);
	}

	public TinySamlClient(final TinySamlClientConfig config) throws IOException {

		
		try {
			InitializationService.initialize();
		} catch (final Throwable t) {
			FileLogUtils.log(t);
		}

		try {
			if (config == null ) {
				authnRequestUtils = null;
				samlResponseUtils = null;
				idpMetadataUtils = null;
				serviceProviderMetadataUtils = null;
			} else {
				final String spMetadataFile = config.getServiceProviderMetadataFile();
				serviceProviderMetadataUtils = new ServiceProviderMetadataUtils(spMetadataFile);
				idpMetadataUtils = new IdpMetadataUtils(config);
				authnRequestUtils = new AuthnRequestUtils(serviceProviderMetadataUtils, config.getServiceProviderSigningKeyLocation());
				samlResponseUtils = new SAMLResponseUtils(idpMetadataUtils, serviceProviderMetadataUtils);
			}
		} catch (final Exception e) {
			LOGGER.error(e.getMessage(), e);
			FileLogUtils.log(e);
			throw e;
		}

	}

	/**
	 * Builds a SAML2 AuthnRequest and encodes it for the appropriate binding, ready to put into a HTML response.
	 * 
	 * @param sign whether or not to sign the request
	 * @return
	 */
	public final String buildSAMLRequest(final boolean sign) {
		AuthnRequest request = authnRequestUtils.buildAuthnRequest(sign);
		return AuthnRequestUtils.wireEncodeAuthRequest(request);
	}

	/**
	 * Returns the endpoint URL for the IDP that matches the Service Provider's preferred binding
	 * @return a URL for either the POST or Redirect bindings, per service provider metadata preference
	 */
	public final String getIdpSSOUrl() {
		return idpMetadataUtils.getIdpSsoUrl();
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
			LOGGER.error("Response failed validation", e);
			throw new RuntimeException(e);
		}
	}
}
 