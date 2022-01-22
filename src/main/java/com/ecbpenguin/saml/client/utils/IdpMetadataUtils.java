package com.ecbpenguin.saml.client.utils;

import java.util.Iterator;
import java.util.List;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.FileBackedHTTPMetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import com.ecbpenguin.saml.config.TinySamlClientConfig;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;

public class IdpMetadataUtils {

	private static final long METADATA_REFRESH_DELAY_MS = 60 * 60 * 1000; // 1 hour for DEV

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
			metadataResolver.setBackupFileInitNextRefreshDelay(METADATA_REFRESH_DELAY_MS);
		} catch (final ResolverException e) {
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
			final IDPSSODescriptor idpSsoDescriptor = entity.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
			if (idpSsoDescriptor != null) {
				foundCert = MetadataCertificateUtils.getSigningX509Certifate(idpSsoDescriptor);
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
