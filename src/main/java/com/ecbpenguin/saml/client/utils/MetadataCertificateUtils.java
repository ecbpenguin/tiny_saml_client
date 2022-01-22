package com.ecbpenguin.saml.client.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Data;

/**
 * 
 * @author ecb_penguin
 *
 */
public class MetadataCertificateUtils {

	/**
	 * Extracts the X509 Certificate from a metadata file for various uses (e.g. signing, signature validation)
	 * 
	 * @param roleDescriptor a Metadata descriptor (e.g. SPSSODescriptor, IDPSSODescriptor)
	 * @return the signing X509Certificate
	 */
	public static X509Certificate getSigningX509Certifate(final RoleDescriptor roleDescriptor) {
		for (final KeyDescriptor kd : roleDescriptor.getKeyDescriptors()) {
			final UsageType usage = kd.getUse();
			if (UsageType.SIGNING.equals(usage) || UsageType.UNSPECIFIED.equals(usage)) {
				return extractX509Certificate(kd);
			}
		}
		return null;
	}

	private static final X509Certificate extractX509Certificate(final KeyDescriptor keyDescriptor) {
		final KeyInfo keyInfo = keyDescriptor.getKeyInfo();
		if (keyInfo == null) {
			return null;
		}

		final List<X509Data> x509Datas = keyInfo.getX509Datas();
		if (x509Datas.size() == 0) {
			return null;
		}

		final X509Data x509Data = x509Datas.get(0);
		final List<org.opensaml.xmlsec.signature.X509Certificate> x509Certificates = x509Data.getX509Certificates();

		if (x509Certificates.size() == 0) {
			return null;
		}
		final org.opensaml.xmlsec.signature.X509Certificate openSamlCert = x509Certificates.get(0);
		final String lexicalXSDBase64Binary = openSamlCert.getValue();
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
					//  TODO log this logging will initialize
				}
			}
		}

		return cert;
	}

}
