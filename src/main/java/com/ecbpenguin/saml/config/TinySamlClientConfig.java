package com.ecbpenguin.saml.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Configuration holder
 * 
 * @author ecb_penguin
 *
 */
public class TinySamlClientConfig {

	private static final String SP_METADATA_FILE_KEY = "tinySamlClient.serviceProviderMetadataFileLocation";

	private static final String SP_SIGNING_KEY_LOCATION_KEY = "tinySamlClient.serviceProviderSigningKeyLocation";

	private static final String IDP_METADATA_URL_KEY = "tinySamlClient.idpMetadataUrl";

	private static final String IDP_METADATA_CACHE_LOCATION = "tinySamlClient.idpFileCacheLocation";

	private final String serviceProviderMetadataFile;

	private final String idpMetadataCacheLocation;

	private final String idpMetadataUrl;

	private final String serviceProviderSigningKeyLocation;

	public TinySamlClientConfig(final String tinySamlClientConfigFile) {

		final File f = new File(tinySamlClientConfigFile).getAbsoluteFile();
		final Properties tinySamlClientProps = new Properties();
		InputStream is = null;
		try {
			is = new FileInputStream(f);
			tinySamlClientProps.load(is);
		} catch (final IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			if (is != null ) {
				try {
					is.close();
				} catch (final IOException e) {
					// TODO log this somehow
				}
			}
		}

		// validate that you have all the properties you need 
		final Object serviceProviderMetadataFileObj =  tinySamlClientProps.getOrDefault(SP_METADATA_FILE_KEY, null);
		if (serviceProviderMetadataFileObj == null ||
				serviceProviderMetadataFileObj instanceof String) {
			serviceProviderMetadataFile = (String)serviceProviderMetadataFileObj;
		} else {
			throw new IllegalArgumentException("Property " + SP_METADATA_FILE_KEY + " not found or not castable to a String in " + tinySamlClientConfigFile);
		}
	
		final Object idpMetadataUrlObj = tinySamlClientProps.getOrDefault(IDP_METADATA_URL_KEY, null);
		if (idpMetadataUrlObj != null && idpMetadataUrlObj instanceof String) {
			idpMetadataUrl = (String)idpMetadataUrlObj;
		} else {
			throw new IllegalArgumentException("Property " + IDP_METADATA_URL_KEY + " not found or not castable to a String in " + tinySamlClientConfigFile);
		}

		final Object idpMetadataCacheLocationObj = tinySamlClientProps.getOrDefault(IDP_METADATA_CACHE_LOCATION, null);
		if (idpMetadataCacheLocationObj != null && idpMetadataCacheLocationObj instanceof String) {
			idpMetadataCacheLocation = (String)idpMetadataCacheLocationObj;
		} else {
			throw new IllegalArgumentException("Property " + IDP_METADATA_CACHE_LOCATION + " not found or not castable to a String in " + tinySamlClientConfigFile);
		}

		final Object signingKeyLocation = tinySamlClientProps.getOrDefault(SP_SIGNING_KEY_LOCATION_KEY, null);
		if (signingKeyLocation != null && signingKeyLocation instanceof String) {
			serviceProviderSigningKeyLocation = (String)signingKeyLocation;
		} else {
			serviceProviderSigningKeyLocation = null;
		}
	}

	public String getServiceProviderMetadataFile() {
		return serviceProviderMetadataFile;
	}

	public String getIdpMetadataCacheLocation() {
		return idpMetadataCacheLocation;
	}

	public String getIdpMetadataUrl() {
		return idpMetadataUrl;
	}

	public String getServiceProviderSigningKeyLocation() {
		return serviceProviderSigningKeyLocation;
	}
}
