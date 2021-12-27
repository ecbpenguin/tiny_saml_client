package com.ecbpenguin.saml.client.utils;

import java.io.File;
import java.util.Iterator;
import java.util.List;

import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;

public class ServiceProviderMetadataUtils {


	private static final Logger LOGGER = LoggerFactory.getLogger(AuthnRequestUtils.class);

	private final String spEntityId;

	private final String spNameFormat;

	private final String protocolBinding;

	private final String assertionConsumerServiceUrl;
	
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
				LOGGER.debug("Inspecting {}", ed);
				List<RoleDescriptor> roles = ed.getRoleDescriptors();
				// hack-ish, should have closer bounds checking on the role descriptor being tested
				for (RoleDescriptor r : roles) {
					LOGGER.debug("Testing {}: {}",  r, r.getID());
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
		List<NameIDFormat> nameIDFormats =spSSODescriptor.getNameIDFormats();
		if (nameIDFormats != null && nameIDFormats.size() > 0) {
			// in practice there's only ever one
			spNameFormat = nameIDFormats.get(0).getFormat();
		} else {
			LOGGER.warn("No SP Name format identified!");
			spNameFormat = "";//unspecified
		}
		List<AssertionConsumerService> acss = spSSODescriptor.getAssertionConsumerServices();
		if (acss != null && acss.size() > 0) {
			assertionConsumerServiceUrl = acss.get(0).getLocation();
			protocolBinding = acss.get(0).getBinding();
		} else {
			throw new IllegalArgumentException("Cannot infer an Assertion Consumer Service URL");
		}
		
	}

	public final String getSpEntityId() {
		return spEntityId;
	}

	public String getAssertionConsumerServiceUrl() {
		return assertionConsumerServiceUrl;
	}

	public String getProtocolBinding() {
		return protocolBinding;
	}

	public String getSpNameFormat() {
		return spNameFormat;
	}
}
