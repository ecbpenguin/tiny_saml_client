package com.ecbpenguin.saml.client.utils;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;

public class ServiceProviderMetadataUtils {

	private final String spEntityId;

	private final String spNameFormat;

	private final String protocolBinding;

	private final String assertionConsumerServiceUrl;

	private final X509Certificate signingCertificate;

	public ServiceProviderMetadataUtils(final String spMetadata) {
		SPSSODescriptor spSSODescriptor = null;
		String serviceProviderEntityId = null;
		try {
			final File spMetadataFile = new File(spMetadata);
			final FilesystemMetadataResolver serviceProviderMetadataResolver = new FilesystemMetadataResolver(spMetadataFile);
			final BasicParserPool pp = new BasicParserPool();
			pp.initialize();

			serviceProviderMetadataResolver.setId(spMetadataFile.getName());
			serviceProviderMetadataResolver.setParserPool(pp);
			serviceProviderMetadataResolver.initialize();
			
			final Iterator<EntityDescriptor> ei = serviceProviderMetadataResolver.iterator();
			while (ei.hasNext()) {
				final EntityDescriptor ed = ei.next();
				final List<RoleDescriptor> roles = ed.getRoleDescriptors();
				// hack-ish, should have closer bounds checking on the role descriptor being tested
				for (final RoleDescriptor r : roles) {
					if (r instanceof SPSSODescriptor) {
						// this is the entity that you're going to use, so set the entity ID here
						serviceProviderEntityId = ed.getEntityID();
						spSSODescriptor = (SPSSODescriptor)r;
					}
				}
			} 
		} catch (final ResolverException | ComponentInitializationException e) {
			throw new IllegalArgumentException(e);
		}
		if (spSSODescriptor == null) {
			// configuration error
			throw new IllegalArgumentException("Service provider metadata needs to contain a SP SSO descriptor!");
		}

		// keeps things 'final'
		spEntityId = serviceProviderEntityId;
		final List<NameIDFormat> nameIDFormats =spSSODescriptor.getNameIDFormats();
		if (nameIDFormats != null && nameIDFormats.size() > 0) {
			// in practice there's only ever one
			spNameFormat = nameIDFormats.get(0).getFormat();
		} else {
			spNameFormat = "";//unspecified
		}
		final List<AssertionConsumerService> acss = spSSODescriptor.getAssertionConsumerServices();
		if (acss != null && acss.size() > 0) {
			assertionConsumerServiceUrl = acss.get(0).getLocation();
			protocolBinding = acss.get(0).getBinding();
		} else {
			throw new IllegalArgumentException("Cannot infer an Assertion Consumer Service URL");
		}

		signingCertificate = MetadataCertificateUtils.getSigningX509Certifate(spSSODescriptor);
	}

	public final String getSpEntityId() {
		return spEntityId;
	}

	public final String getAssertionConsumerServiceUrl() {
		return assertionConsumerServiceUrl;
	}

	public final String getProtocolBinding() {
		return protocolBinding;
	}

	public final String getSpNameFormat() {
		return spNameFormat;
	}

	public final X509Certificate getSigningCertificate() {
		return signingCertificate;
	}
}
