package com.ecbpenguin.saml.client.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FileBackedHTTPMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ecbpenguin.saml.config.TinySamlClientConfig;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;

public class IdpMetadataUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(IdpMetadataUtils.class);

	private final FileBackedHTTPMetadataResolver metadataResolver;

	//not final because the class throws this away when validation fails
	private Credential idpSigningCredential;

	private String idpEndpoint;

	public IdpMetadataUtils(final TinySamlClientConfig config) {
		final HttpClient httpClient = HttpClientBuilder.create().build();
		// place to write the cache to, TMP is great because the code by default has r/w access to it, and it 
		// will exist because the JVM created it
		final String tmpDir = config.getIdpMetadataCacheLocation();

		try {
			// AbstractReoladingMetadataResolver will check the idpMetadataUrl for well-formed-ness
			metadataResolver = new FileBackedHTTPMetadataResolver(httpClient, config.getIdpMetadataUrl(), tmpDir);
		} catch (final ResolverException e) {
			LOGGER.error("Failed to initialize Metadata Resolver", e);
			throw new RuntimeException(e);
		}

		// component identifiers can not be null, but it's just a local ID.
		metadataResolver.setId("saml-idp-metadata-resolver");

		// parser pool is used to marshall / unmarshall XML to and from objects
		BasicParserPool pp = new BasicParserPool();
		try {
			pp.initialize();
			metadataResolver.setParserPool(pp);
			metadataResolver.initialize();
		} catch (final ComponentInitializationException e) {
			LOGGER.error("Failed to initialize parser pool", e);
			throw new RuntimeException(e);
		}
		updateIdpSigningCredential();
	}

	// synchronizing this prevents duplicate updates and minimizes thrashing when the credential changes
	private synchronized void updateIdpSigningCredential() {
		final Iterator<EntityDescriptor> entities = metadataResolver.iterator();
		java.security.cert.X509Certificate foundCert = null;
		String endpointUri = null;
		while (entities.hasNext()) {
			final EntityDescriptor entity = entities.next();
			LOGGER.debug("Checking entity descriptor: {}", entity.getEntityID());
			final IDPSSODescriptor idpSsoDescriptor = entity.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
			LOGGER.debug("Found IDP SSO Descriptor {}", idpSsoDescriptor);
			if (idpSsoDescriptor != null) {
				for (final KeyDescriptor kd : idpSsoDescriptor.getKeyDescriptors()) {
					final UsageType usage = kd.getUse();
					if (UsageType.SIGNING.equals(usage) || UsageType.UNSPECIFIED.equals(usage)) {
						foundCert =getX509Certificate(kd);
					}
				}
				final List<SingleSignOnService> ssoServices = idpSsoDescriptor.getSingleSignOnServices();
				for (final SingleSignOnService ssoService : ssoServices) {
					if (SAMLConstants.SAML2_POST_BINDING_URI.equalsIgnoreCase(ssoService.getBinding())) {
						endpointUri = ssoService.getLocation();
					}
					
				}
			}
		}

		if (foundCert != null ) {
			idpSigningCredential = new BasicX509Credential(foundCert);
			idpEndpoint = endpointUri;
		}
	}

	private java.security.cert.X509Certificate getX509Certificate(final KeyDescriptor keyDescriptor) {
		final KeyInfo keyInfo = keyDescriptor.getKeyInfo();
		if (keyInfo == null) {
			return null;
		}

		final List<X509Data> x509Datas = keyInfo.getX509Datas();
		if (x509Datas.size() == 0) {
			return null;
		}

		final X509Data x509Data = x509Datas.get(0);
		final List<X509Certificate> x509Certificates = x509Data.getX509Certificates();

		if (x509Certificates.size() == 0) {
			return null;
		}
		X509Certificate openSamlCert = x509Certificates.get(0);
		String lexicalXSDBase64Binary = openSamlCert.getValue();
		byte[] decodedString = Base64.getDecoder().decode(new String(lexicalXSDBase64Binary).getBytes());

		
		java.security.cert.X509Certificate cert = null;
		ByteArrayInputStream bais = null;
		try {
			bais = new ByteArrayInputStream(decodedString);
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			cert = (java.security.cert.X509Certificate) certFactory.generateCertificate(bais);
		} catch (final CertificateException e) {
			//thrown when ...
			throw new RuntimeException(e);
		} finally {
			if (bais != null ) {
				try {
					bais.close();
				} catch (final IOException e) {
					//eat this, alert about possible memory leak.
					LOGGER.warn("Exception in resource closing, possible memory leak!", e);
				}
			}
		}

		return cert;
	}

	public final String getIdpSsoUrl() {
		return idpEndpoint;
	}

	public boolean validateIdpSignature(final Signature signature) throws SignatureException {
		boolean valid = false;
		SignatureException rootCause = null;
		try {
			SignatureValidator.validate(signature, idpSigningCredential);
			valid = true;
		} catch ( final SignatureException e) {
			rootCause = e;
			valid = false;
		}
		if (valid) {
			return true;
		}

		//not valid, try to refresh the signing credential (e.g. a regular metadata refresh that we've aready cached)
		updateIdpSigningCredential();
		try {
			SignatureValidator.validate(signature, idpSigningCredential);
			valid = true;
		} catch ( final SignatureException e) {
			rootCause = e;
			valid = false;
		}
		
		if (valid) {
			return true;
		}

		//now try to force refresh the metadata (e.g. we haven't picked up the new cert yet from the IDP)
		try {
			metadataResolver.refresh();
		} catch (final ResolverException e) {
			//can't refresh, could be in the middle of a ADFS refresh.
			// fail and let the next iteration try again
			return false;
		}

		updateIdpSigningCredential();
		try {
			SignatureValidator.validate(signature, idpSigningCredential);
			valid = true;
		} catch ( final SignatureException e) {
			rootCause = e;
			valid = false;
		}

		if (rootCause != null) {
			throw rootCause;
		}
		//this means the refresh was valid and resulted in a successful validation
		return valid;
	}
	
}
