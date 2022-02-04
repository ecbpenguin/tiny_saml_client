package com.ecbpenguin.saml.client.utils;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

/**
 * Encapsulates anything necessary to generate a SAML v2 AuthnRequest
 * @author ecb_penguin
 *
 */
public class AuthnRequestUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthnRequestUtils.class);

	private final ServiceProviderMetadataUtils serviceProviderMetadataUtils;

	private final BasicX509Credential signingCredential;

	public AuthnRequestUtils(final ServiceProviderMetadataUtils spMetadataUtils, final String privateKeyLocation) throws IOException {
		this.serviceProviderMetadataUtils = spMetadataUtils;
		if (privateKeyLocation != null && privateKeyLocation.length() > 0) {
			final PrivateKey privateKey = loadPrivateKey(privateKeyLocation);
			final X509Certificate signingCertificate = spMetadataUtils.getSigningCertificate();
			this.signingCredential = new BasicX509Credential(signingCertificate, privateKey);
		} else {
			this.signingCredential = null;
		}
	}

	private final PrivateKey loadPrivateKey(final String privateKeyLocation) throws IOException {
		RandomAccessFile raf = null;
		LOGGER.debug("Loading private key from {}", privateKeyLocation);
		try {
			raf  = new RandomAccessFile(privateKeyLocation, "r");
			final byte[] buf = new byte[(int) raf.length()];
			raf.readFully(buf);
			final String temp = new String(buf);
			String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----", "");
			privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
			privKeyPEM = privKeyPEM.replaceAll("(?:\\n|\\r)", "");

			byte [] decoded = Base64.getDecoder().decode(privKeyPEM);
			PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(decoded);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(kspec);
		} catch (final IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			LOGGER.error(e.getMessage(), e);
			throw new IOException("Private key file doesn't exist", e);
		} finally {
			if (raf!= null) {
				try {
					raf.close();
				} catch (final IOException e2) {
					LOGGER.warn("Hanging file handle: {}", e2.getMessage(), e2);
				}
			}
		}
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

		if (sign && signingCredential != null) {
			try {
				signRequest(authnRequest);
			} catch (final IOException e) {
				LOGGER.error("Could not sign request.  Passing unsigned AuthnRequest {}", e.getMessage(), e);
			}
		}
		return authnRequest;
	}

	private void signRequest(final SignableSAMLObject samlObject) throws IOException {

		// Describe how we're going to sign the request
		SignatureBuilder signer = new SignatureBuilder();
		Signature signature = signer.buildObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

		try {
			signature.setKeyInfo(new X509KeyInfoGeneratorFactory().newInstance().generate(signingCredential));
		} catch (final org.opensaml.security.SecurityException e) {
			throw new IOException("Failed to sign request", e);
		}
		signature.setSigningCredential(signingCredential);
		samlObject.setSignature(signature);

		final SignatureSigningParameters signingParameters = createSignatureSigningParameters();
		try {
			SignatureSupport.signObject(samlObject, signingParameters);
		} catch (final org.opensaml.security.SecurityException | MarshallingException | SignatureException e) {
			throw new IOException("Failed to sign request", e);
		}
	}

	private SignatureSigningParameters createSignatureSigningParameters() {
		SignatureSigningParameters signingParameters = new SignatureSigningParameters();
		signingParameters.setSigningCredential(signingCredential);
		signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signingParameters.setKeyInfoGenerator(new X509KeyInfoGeneratorFactory().newInstance());
		return signingParameters;
	}

	public final String wireEncodePostRequest(final AuthnRequest authnRequest) {
		LOGGER.debug("Encoding AuthnRequest: {}",  authnRequest);
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
			LOGGER.error("Count not marshall to DOM tree: {}", e.getMessage(), e);
			throw new RuntimeException(e);
		}

		final String rawXmlResponse  = result.getWriter().toString();
		final String base64RequestMessage = Base64.getEncoder().withoutPadding().encodeToString(rawXmlResponse.getBytes());
		LOGGER.debug("Wire encoded authnRequest to {}", base64RequestMessage);
		return base64RequestMessage;
	}

	public final String wireEncodeRedirectRequest(final AuthnRequest authnRequest, final String idpEndpointUrl) throws IOException {

		if (authnRequest == null || idpEndpointUrl == null) {
			return null;
		}

		final MessageContext<SAMLObject> messageContext = new MessageContext<>();
		messageContext.setMessage(authnRequest);

		// This moved out of the Configuration class
		final XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

		@SuppressWarnings("unchecked")
		final SAMLObjectBuilder<Endpoint> endpointBuilder =
		(SAMLObjectBuilder<Endpoint>) builderFactory.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);

		// Endpoint is now set via subcontexts
		final SAMLPeerEntityContext peerEntityContext = messageContext.getSubcontext(SAMLPeerEntityContext.class, true);
		final SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
		final Endpoint samlEndpoint = endpointBuilder.buildObject();
		samlEndpoint.setLocation(idpEndpointUrl);
		endpointContext.setEndpoint(samlEndpoint);

		final SecurityParametersContext securityContext = messageContext.getSubcontext(SecurityParametersContext.class, true);
		final SignatureSigningParameters signingParameters = createSignatureSigningParameters();
		securityContext.setSignatureSigningParameters(signingParameters);
		messageContext.addSubcontext(securityContext, true);
		// MessageContext and HttpServletResponse now get set directly on the encoder
		final StringHTTPRedirectDeflateEncoder httpRedirectDeflateEncoder = new StringHTTPRedirectDeflateEncoder();
		httpRedirectDeflateEncoder.setMessageContext(messageContext);
		String redirectUrl =null;
		try {
			// we are not initializing because all that's doing is checking for a context and a http servlet response
			// we don't have a http servlet response. 
			//httpRedirectDeflateEncoder.initialize();
			redirectUrl = httpRedirectDeflateEncoder.createEncodedRequest();
		} catch (final MessageEncodingException e) {
			LOGGER.error("Could not encode request {}", e);
			throw new IOException(e);
		} 
		return redirectUrl;
	}
}
