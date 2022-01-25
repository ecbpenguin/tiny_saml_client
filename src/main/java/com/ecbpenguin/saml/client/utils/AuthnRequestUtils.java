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
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.w3c.dom.Element;

import com.ecbpenguin.utils.FileLogUtils;

/**
 * Encapsulates anything necessary to generate a SAML v2 AuthnRequest
 * @author ecb_penguin
 *
 */
public class AuthnRequestUtils {

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
		try {
			raf  = new RandomAccessFile(privateKeyLocation, "r");
			final byte[] buf = new byte[(int) raf.length()];
			raf.readFully(buf);
			PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(kspec);
		} catch (final IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			FileLogUtils.log(e);
			throw new IOException("Private key file doesn't exist", e);
		} finally {
			if (raf!= null) {
				try {
					raf.close();
				} catch (final IOException e2) {
					// TODO log this once we clean up logging
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
				// TODO log this
				// letting an unsigned request flow through
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

		// Actually sign the request
		SignatureSigningParameters signingParameters = new SignatureSigningParameters();
		signingParameters.setSigningCredential(signingCredential);
		signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		signingParameters.setKeyInfoGenerator(new X509KeyInfoGeneratorFactory().newInstance());
		try {
			SignatureSupport.signObject(samlObject, signingParameters);
		} catch (final org.opensaml.security.SecurityException | MarshallingException | SignatureException e) {
			throw new IOException("Failed to sign request", e);
		}
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
