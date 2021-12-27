package com.ecbpenguin.saml.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration holder
 * 
 * @author ecb_penguin
 *
 */
public class TinySamlClientConfig {

	private static final Logger LOGGER = LoggerFactory.getLogger(TinySamlClientConfig.class);

	private static final String SP_METADATA_FILE_KEY = "tinySamlClient.serviceProviderMetadataFileLocation";

	private static final String SP_SIGNING_KEY_LOCATION = "tinySamlClient.serviceProviderSigningKeyLocation";

	private static final String SP_SIGNING_KEY_ALIAS = "tinySamlClient.serviceProviderKeyAlias";

	private static final String IDP_METADATA_URL_KEY = "tinySamlClient.idpMetadataUrl";

	private static final String IDP_METADATA_CACHE_LOCATION = "tinySamlClient.idpFileCacheLocation";

	private final String serviceProviderMetadataFile;

	private final String idpMetadataCacheLocation;

	private final String idpMetadataUrl;

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
					LOGGER.warn("Unable to close config file handle.  Probably memory leak.",  e);
				}
			}
		}

		// validate that you have all the properties you need 
		Object serviceProviderMetadataFileObj =  tinySamlClientProps.get(SP_METADATA_FILE_KEY);
		if (serviceProviderMetadataFileObj == null ||
				serviceProviderMetadataFileObj instanceof String) {
			serviceProviderMetadataFile = (String)serviceProviderMetadataFileObj;
		} else {
			throw new IllegalArgumentException("Property " + SP_METADATA_FILE_KEY + " not found or not castable to a String in " + tinySamlClientConfigFile);
		}
	
		Object idpMetadataUrlObj = tinySamlClientProps.get(IDP_METADATA_URL_KEY);
		if (idpMetadataUrlObj != null && idpMetadataUrlObj instanceof String) {
			idpMetadataUrl = (String)idpMetadataUrlObj;
		} else {
			throw new IllegalArgumentException("Property " + IDP_METADATA_URL_KEY + " not found or not castable to a String in " + tinySamlClientConfigFile);
		}

		Object idpMetadataCacheLocationObj = tinySamlClientProps.get(IDP_METADATA_CACHE_LOCATION);
		if (idpMetadataCacheLocationObj != null && idpMetadataCacheLocationObj instanceof String) {
			idpMetadataCacheLocation = (String)idpMetadataCacheLocationObj;
		} else {
			throw new IllegalArgumentException("Property " + IDP_METADATA_CACHE_LOCATION + " not found or not castable to a String in " + tinySamlClientConfigFile);
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
}
