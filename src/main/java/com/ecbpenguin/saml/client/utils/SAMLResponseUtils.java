package com.ecbpenguin.saml.client.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.ecbpenguin.utils.FileLogUtils;

/**
 * This class employs OpenSAML classes to validate a SAML Response. It needs augmentation for
 * 1. In Response To metrics = the caller would need to retain the original SAML request to perform this validation
 * 2. Message replay: in a clustered scenario, there needs to be a shared state mechanism (e.g. a database table) 
 * to store message IDs in a replay cache.
 *
 * @author ecbpenguin
 *
 */
public class SAMLResponseUtils {

	private static final int CLOCK_SKEW_SECONDS = 30;

	private final DocumentBuilder documentBuilder; 

	private final UnmarshallerFactory unmarshallerFactory;

	private final IdpMetadataUtils idpMetadataUtils;

	private final ServiceProviderMetadataUtils serviceProviderMetadataUtils;
	
	public SAMLResponseUtils(final IdpMetadataUtils idpMetadataUtils, final ServiceProviderMetadataUtils serviceProviderMetadataUtils) {
		if (serviceProviderMetadataUtils == null) {
			throw new IllegalArgumentException("serviceProviderMetadataUtils must not be null!");
		}
		if (idpMetadataUtils == null) {
			throw new IllegalArgumentException("idpMetadataUtils must not be null!");
		}
		final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);

		try {
			documentBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (final ParserConfigurationException e) {
			FileLogUtils.log(e);
			throw new RuntimeException(e);
		}

		this.unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
		this.idpMetadataUtils = idpMetadataUtils;
		this.serviceProviderMetadataUtils = serviceProviderMetadataUtils;
	}

	private void checkAssertions(final Response response) throws IOException {
		// a response can only have one assertion
		final List<Assertion> assertions = response.getAssertions();
		if (assertions == null || assertions.size() != 1) {
			throw new IOException("Response must contain at least one assertion!");
		}
	}

	private void checkConditions(final Assertion assertion) throws IOException {
		final Conditions conditions = assertion.getConditions();
		if (conditions == null) {
			//optional element
			return;
		}
		
		final List<AudienceRestriction> audienceRestrictions =conditions.getAudienceRestrictions();
		final String spEntityId =serviceProviderMetadataUtils.getSpEntityId();
		if (audienceRestrictions != null && audienceRestrictions.size() > 0) {
			boolean found = false;
			for (final AudienceRestriction audienceRestriction : audienceRestrictions) {
				final List<Audience> audiences=  audienceRestriction.getAudiences();
				if (audiences != null && audiences.size() > 0) {
					for (final Audience audience : audiences) {
						final String audienceUri = audience.getAudienceURI();
						if (audienceUri != null && spEntityId.equalsIgnoreCase(audienceUri)) {
							found = true;
						}
					}
				}
			}
			
			if (!found ) {
				throw new IOException("Audience not found in restrictions");
			}
		}
		final DateTime notBefore = conditions.getNotBefore();
		final DateTime notOnOrAfter = conditions.getNotOnOrAfter();
		
		checkNotBefore(notBefore);
		checkNotOnOrAfter(notOnOrAfter);
	}

	private void checkNotOnOrAfter(final DateTime notOnOrAfter) throws IOException {
		final DateTime skewedTime = getSkewedTime();
		if (notOnOrAfter != null && skewedTime.isAfter(notOnOrAfter)) {
			throw new IOException("Not on or after condition violated for time = " + notOnOrAfter);
		}
	}

	private void checkNotBefore(final DateTime notBefore) throws IOException {
		final DateTime skewedTime = getSkewedTime();
		if (notBefore != null && skewedTime.isBefore(notBefore)) {
			throw new IOException("Not before condition violated for time = " + notBefore);
		}
	}

	private void checkSignature(final Response response) throws IOException {
		final Signature responseSignature = response.getSignature();
		if (responseSignature != null ) {
			boolean valid = false;
			try {
				valid = idpMetadataUtils.validateIdpSignature(responseSignature);
			} catch (final SignatureException e) {
				throw new IOException(e);
			}
			if (!valid) {
				throw new IOException("SAML Signature not valid!");
			}
		}

		// HAS to be called after you check assertions 
		final Assertion assertion = response.getAssertions().get(0);
		final Signature assertionSignature = assertion.getSignature();
		if (assertionSignature != null ) {
			boolean valid = false;
			try {
				valid = idpMetadataUtils.validateIdpSignature(assertionSignature);
			} catch (final SignatureException e) {
				throw new IOException(e);
			}
			if (!valid) {
				throw new IOException("SAML Signature not valid!");
			}
		}
	}
	private void checkStatus(final Response response) throws IOException {
		final Status status = response.getStatus();
		if (status == null) {
			throw new IOException ("Response does not contain a status");
		}
		final StatusCode statusCode = status.getStatusCode();
		if (statusCode == null) {
			throw new IOException("Status must contain a status code");
		}

		final String codeValue =statusCode.getValue();
		if (codeValue == null || !StatusCode.SUCCESS.equalsIgnoreCase(codeValue)) {
			throw new IOException("Status code was not successful");
		}
	}

	private void checkSubjectConfirmationData(final Subject subject) throws IOException {
		boolean hasScd = false;
		final List<SubjectConfirmation> subjectConfirmations = subject.getSubjectConfirmations();
		if (subjectConfirmations != null && subjectConfirmations.size() > 0) {
			for (final SubjectConfirmation subjectConfirmation : subjectConfirmations) {
				hasScd = true;
				final SubjectConfirmationData scd = subjectConfirmation.getSubjectConfirmationData();
				// don't have the state to check InResponseTo
				// scd.getInResponseTo();
				// check timings in subject confirmation data as well
				final DateTime notBefore = scd.getNotBefore();
				final DateTime notOnOrAfter = scd.getNotOnOrAfter();
				checkNotBefore(notBefore);
				checkNotOnOrAfter(notOnOrAfter);
				final String recipient = scd.getRecipient();
				if (recipient != null && !serviceProviderMetadataUtils.getAssertionConsumerServiceUrl().equalsIgnoreCase(recipient) ) {
					throw new IOException("Recipient did not match assertion consumer service URL!");
				}
			}
		}
		if (!hasScd) {
			throw new IOException("Subject MUST contain a subject confirmation data element!");
		}
	}

	private void checkDestination(final Response response) throws IOException {
		final String destination = response.getDestination();
		if (destination == null || ! destination.equalsIgnoreCase(serviceProviderMetadataUtils.getAssertionConsumerServiceUrl())) {
			throw new IOException("Response did not have the appropriate destionation = " + serviceProviderMetadataUtils.getAssertionConsumerServiceUrl());
		}
	}
	private final String decodeBase64Response(final String base64EncodedRespnse) {
		final byte[] decodedBytes = Base64.getDecoder().decode(base64EncodedRespnse);
		return new String(decodedBytes);
	}

	/**
	 * Returns the name ID associated with the response.
	 * 
	 * Does NOT support encrypted Name IDs.
	 * 
	 * @param assertion
	 * @return
	 * @throws IOException
	 */
	private final String getNameID(final Subject subject) throws IOException {
		final NameID nameId =subject.getNameID();
		if (nameId == null) {
			throw new IOException("Name ID not included in subject");
		}
		return nameId.getValue();
	}

	private final DateTime getSkewedTime() {
		return DateTime.now().plusSeconds(SAMLResponseUtils.CLOCK_SKEW_SECONDS);
	}

	private final Subject getSubject(final Assertion assertion) throws IOException {
		final Subject subject = assertion.getSubject();
		if (subject == null) {
			throw new IOException("Assertion did not contain a subject");
		}
		return subject;
	}

	/**
	 * Method to validate a SAML response and extract the name id for mapping by other entities
	 * 
	 * This can be expanded to additional attributes via a wrapper class, should requirements warrant.
	 * 
	 * @param SAMLResponse
	 * @return
	 */
	public final String validateSAMLResponsePostBinding(final String samlResponse) throws IOException {
		return validateSAMLResponsePostBinding(samlResponse, true);
	}

	protected final String validateSAMLResponsePostBinding(final String samlResponse, final boolean checkSignature) throws IOException {
		final String samlResponseString = decodeBase64Response(samlResponse);
		final Response response = unmarshallSamlResponse(samlResponseString);

		if (response == null ) {
			throw new IOException("Unable to extract SAML Response!");
		}

		checkStatus(response);
		checkAssertions(response);
		checkDestination(response);
		final Assertion assertion = response.getAssertions().get(0);
		checkConditions(assertion);
		final Subject subject = getSubject(assertion);
		checkSubjectConfirmationData(subject);

		if (checkSignature) {
			checkSignature(response);
		}
		return getNameID(subject);
	}
	
	private final Response unmarshallSamlResponse(final String samlResponse) {
		ByteArrayInputStream bais = null;
		Document samlResponseDocument = null;
		try {
			bais =new ByteArrayInputStream(samlResponse.getBytes());
			samlResponseDocument = documentBuilder.parse(bais);
		} catch (final SAXException | IOException e) {
			throw new RuntimeException(e);
		} finally {
			if (bais != null) {
				try {
					bais.close();
				} catch (final IOException e) {
					// TODO log me
				}
			}
		}
		

		final Element element = samlResponseDocument.getDocumentElement();
		final Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		
		XMLObject xmlResponseObject = null;
		try {
			xmlResponseObject = unmarshaller.unmarshall(element);
		} catch ( final UnmarshallingException e) {
			throw new RuntimeException(e);
		}

		if (xmlResponseObject instanceof Response) {
			return (Response)xmlResponseObject;
		}

		return null;
	}
}
