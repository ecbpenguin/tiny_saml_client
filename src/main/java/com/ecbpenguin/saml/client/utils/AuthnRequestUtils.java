package com.ecbpenguin.saml.client.utils;

import java.io.StringWriter;
import java.util.Base64;
import java.util.UUID;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

public class AuthnRequestUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthnRequestUtils.class);

	private final ServiceProviderMetadataUtils serviceProviderMetadataUtils;
	
	public AuthnRequestUtils(final ServiceProviderMetadataUtils spMetadataUtils) {
		this.serviceProviderMetadataUtils = spMetadataUtils;
	}

	public final AuthnRequest buildAuthnRequest(final boolean sign) {

		AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
		AuthnRequest authnRequest = authRequestBuilder.buildObject();
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(serviceProviderMetadataUtils.getSpEntityId());
		authnRequest.setIssuer(issuer);

		NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
		NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
		nameIdPolicy.setFormat(serviceProviderMetadataUtils.getSpNameFormat());
		nameIdPolicy.setAllowCreate(true);
		authnRequest.setNameIDPolicy(nameIdPolicy);

		DateTime issueInstant = new DateTime();
		authnRequest.setIssueInstant(issueInstant);
		authnRequest.setProtocolBinding(serviceProviderMetadataUtils.getProtocolBinding());
		authnRequest.setAssertionConsumerServiceURL(serviceProviderMetadataUtils.getAssertionConsumerServiceUrl());

		// ID is a NSToken, which must start with A-Z_, not 0-9, so prepend with an underscore
		final String id = "_" + UUID.randomUUID().toString();
		authnRequest.setID(id);
		authnRequest.setVersion(SAMLVersion.VERSION_20); // safe to hard code this, everything is SAML2
		LOGGER.info("Creating SAML AuthnRequest: {}", authnRequest);
		
		if (sign) {
			// TODO
			LOGGER.error("TODO implement request signing");
		}
		return authnRequest;
	}

	public static final String wireEncodeAuthRequest(final AuthnRequest authnRequest) {
		final Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest);//Configuration.getMarshallerFactory().getMarshaller(authnRequest);
		Element authElement ;
		try {
			authElement = marshaller.marshall(authnRequest);
		} catch (final MarshallingException e) {
			throw new RuntimeException(e);
		}

		// only good for small objects, not particularly memory efficient
		final StreamResult result = new StreamResult(new StringWriter());
		try {
			TransformerFactory
				.newInstance()
				.newTransformer()
				.transform(new DOMSource(authElement), result);
		} catch (final TransformerException e) {
			throw new RuntimeException(e);
		}

		final String rawXmlResponse  = result.getWriter().toString();
		final String base64RequestMessage = Base64.getEncoder().withoutPadding().encodeToString(rawXmlResponse.getBytes());
		return base64RequestMessage;

	}
}
