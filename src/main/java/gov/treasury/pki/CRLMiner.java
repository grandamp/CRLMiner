package gov.treasury.pki;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import com.google.gson.Gson;

import gov.treasury.pki.util.DataUtil;

/*
 * Inputs:
 * 
 * - .p7b file [all FPKI Certs]
 * - .csv file [uri]
 * - .json file [HTTP CRL URI arranged by SKI for the certs in .p7b]
 * 
 *  Outputs:
 *  
 *  - .JSON file [SKI entries with URI array]
 *  
 *  Obtain collection of HTTP CRL uri
 *  
 *  Download each crl, and:
 *  
 *  - note combined CRL;
 *  - Note authority key identifier, and;
 *  - note issuer distribution point uri.
 *  
 *  Use aki to match with ca ski.
 */
public class CRLMiner {

	static Map<String, String[]> crlMap = Collections.synchronizedMap(new HashMap<String, String[]>());

	/*
	 * Primary method
	 */
	public static void main(String[] args) {
		if (args.length != 3) {
			System.out.println(
					"Usage:\n$ java CRLMiner <.p7b file containing certificates> <.csv file containing CRL URI> <.json file of known CRLs to update>");
			System.exit(0);
		}
		/*
		 * First, parse .p7b and identify all of the unique
		 * subjectKeyIdentifiers, then
		 * 
		 * extract all of the CRLs that are asserted in certificates and assign
		 * them to their associated subjectKeyIdentifiers
		 */
		FileInputStream fisCms = null;
		File fileCsv = null;
		FileInputStream fisJson = null;
		FileOutputStream fosJson = null;
		try {
			fisCms = new FileInputStream(args[0]);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		fileCsv = new File(args[1]);
		try {
			fisJson = new FileInputStream(args[2]);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		try {
			fosJson = new FileOutputStream(args[2]);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		CertificateFactory cf = null;
		try {
			cf = CertificateFactory.getInstance("X509");
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}
		Collection<? extends Certificate> certs = null;
		try {
			certs = cf.generateCertificates(fisCms);
		} catch (CertificateException e2) {
			e2.printStackTrace();
		}
		X509Certificate[] certList = certs.toArray(new X509Certificate[certs.size()]);
		for (X509Certificate cert : certList) {
			/*
			 * Get all the extensions for the current cert
			 */
			Extensions exts = getExtensions(cert);
			/*
			 * Lets populate the map with all the FPKI ca certificate
			 * subjectKeyIdentifiers
			 */
			Extension ski = exts.getExtension(Extension.subjectKeyIdentifier);
			SubjectKeyIdentifier skiExt = SubjectKeyIdentifier
					.getInstance(ASN1OctetString.getInstance(ski.getExtnValue()).getOctets());
			String skiHexString = DataUtil.byteArrayToString(skiExt.getKeyIdentifier());
			System.out.println("CA Entry: " + cert.getSubjectX500Principal().getName() + ";"
					+ cert.getIssuerX500Principal().getName() + ";" + skiHexString);
			System.out.println("Adding: " + skiHexString);
			updateMap(skiHexString, new String[0]);
			/*
			 * Next, let's evaluate this certificate and ensure we have the CRL
			 * asserted by the issuing CA subjectKeyIdentifier (by checking CDP
			 * and authorityKeyIdentifier)
			 */
			String[] crlUri = getCdpUris(cert, "http");
			Extension aki = exts.getExtension(Extension.authorityKeyIdentifier);
			AuthorityKeyIdentifier akiExt = AuthorityKeyIdentifier
					.getInstance(ASN1OctetString.getInstance(aki.getExtnValue()).getOctets());
			String akiHexString = DataUtil.byteArrayToString(akiExt.getKeyIdentifier());
			if (null != crlUri && crlUri.length > 0) {
				updateMap(akiHexString, crlUri);
			} else {
				System.out.println("No CRL for: " + DataUtil.byteArrayToString(akiExt.getKeyIdentifier()));
			}
		}
		/*
		 * Create a CertStore for recollection of certificates from the above
		 * collection
		 */
		List<Certificate> cert_list = new ArrayList<Certificate>();
		cert_list.addAll(certs);
		CertStoreParameters cparam = new CollectionCertStoreParameters(cert_list);
		CertStore cstore = null;
		try {
			cstore = CertStore.getInstance("Collection", cparam, "SUN");
		} catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e1) {
			e1.printStackTrace();
		}
		/*
		 * Output our results so far, in JSON
		 */
		String crlJson = new Gson().toJson(crlMap);
		System.out.println(crlJson);
		/*
		 * TODO: Create a rejected CRL URI list, persist, and check future
		 * proposed input.
		 */
		/*
		 * Now, lets iterate through the proposed CRLSw and only update the map
		 * if the CRL signer matches a keyIdentifier
		 * 
		 * For each combined CRL discovered for a given keyIdentifier, use the
		 * issuerDistributionPoint HTTP location in the CRL.
		 * 
		 * Match the iDP (if found) with the sKI in the list. If no iDP found,
		 * then use the input HTTP location.
		 */
		try (BufferedReader br = new BufferedReader(new FileReader(fileCsv))) {
			for (String line; (line = br.readLine()) != null;) {
				/*
				 * First, ensure it is a valid URI
				 */
				URI crlUri = null;
				try {
					crlUri = new URI(line.trim());
				} catch (URISyntaxException e) {
					e.printStackTrace();
				}
				byte[] crlBytes = downloadCRL(crlUri);
				/*
				 * We only care about URLs that return a valid combined CRL
				 */
				if (null != crlBytes) {
					X509CRL currentCrl = null;
					try {
						currentCrl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crlBytes));
					} catch (CRLException e) {
						e.printStackTrace();
					}
					if (null != currentCrl) {
						/*
						 * Check AKI, if in our map, validate signature using
						 * the CA cert's key.
						 * 
						 * We can't really determine AKI since the CRL does not
						 * contain the signing key...
						 */
						byte[] crlAkiBytes = currentCrl.getExtensionValue(Extension.authorityKeyIdentifier.toString());
						if (null != crlAkiBytes) {
							AuthorityKeyIdentifier crlAki = AuthorityKeyIdentifier
									.getInstance(ASN1OctetString.getInstance(crlAkiBytes).getOctets());
							String crlAkiHexString = DataUtil.byteArrayToString(crlAki.getKeyIdentifier());
							System.out.println("CRL Issuer: " + currentCrl.getIssuerX500Principal());
							System.out.println(
									"Checking proposed URI for KeyIdentifer: " + crlAkiHexString + ": " + crlUri);
							/*
							 * TODO: Ensure AKI is in our map before we proceed.
							 * -- Kinda done, checking the store, which is the
							 * source of truth for the map.
							 */
							/*
							 * Verify signature of CRL by pulling the issuing CA
							 * certificate from the cstore using a CertSelector.
							 */
							X509CertSelector skiSelector = new X509CertSelector();
							SubjectKeyIdentifier skiVal = new SubjectKeyIdentifier(
									DataUtil.stringToByteArray(crlAkiHexString));
							System.out.println(
									"Searching for SKI Value: " + DataUtil.byteArrayToString(skiVal.getEncoded()));
							skiSelector.setSubjectKeyIdentifier(skiVal.getEncoded());
							Collection<? extends Certificate> certsFromSelector = null;
							try {
								certsFromSelector = cstore.getCertificates(skiSelector);
							} catch (CertStoreException e) {
								e.printStackTrace();
							}
							if (certsFromSelector != null && certsFromSelector.size() > 0) {
								X509Certificate signingCA = (X509Certificate) certsFromSelector.toArray()[0];
								try {
									currentCrl.verify(signingCA.getPublicKey());
								} catch (InvalidKeyException | CRLException | NoSuchAlgorithmException
										| NoSuchProviderException | SignatureException e) {
									e.printStackTrace();
								}
								/*
								 * Ensure the CRL type is actually combined, via
								 * id-ce-issuingDistributionPoint OBJECT
								 * IDENTIFIER ::= { id-ce 28 }
								 */
								byte[] crlIdpBytes = currentCrl
										.getExtensionValue(Extension.issuingDistributionPoint.toString());
								if (null != crlIdpBytes) {
									IssuingDistributionPoint idp = IssuingDistributionPoint
											.getInstance(ASN1OctetString.getInstance(crlIdpBytes).getOctets());
									if (idp.onlyContainsUserCerts() || idp.onlyContainsCACerts()
											|| idp.onlyContainsAttributeCerts()) {
										System.out.println("Not a combined CRL: " + crlAkiHexString + ": " + crlUri);
									}
								} else {
									/*
									 * Check for an IssuingDistributionPoint
									 * HTTP URI, and prefer it over the one
									 * submitted, noting the rejection
									 */
									System.out.println("No iDP CRL extension, assuming full and correct CRL: "
											+ crlAkiHexString + ": " + crlUri);
									if (crlMap.containsKey(crlAkiHexString)) {
										updateMap(crlAkiHexString, new String[] { crlUri.toString() });
									}
								}
							} else {
								System.out.println(
										"No signer in our store, rejecting: " + crlAkiHexString + ": " + crlUri);
							}
						} else {
							System.out.println("Rejecting CRL URL due to no KeyIdentifier: " + crlUri);
						}
					}
				}
			}
			crlJson = new Gson().toJson(crlMap);
			fosJson.write(crlJson.getBytes());
			fosJson.flush();
			fosJson.close();
			System.out.println(crlJson);
			for (Entry<String, String[]> entry : crlMap.entrySet()) {
				String currentKey = entry.getKey();
				String[] currentValue = entry.getValue();
				if (currentValue.length == 0) {
					System.out.println("No CRL for the CA with an SKI value of: " + currentKey);
					X509CertSelector skiSelector = new X509CertSelector();
					SubjectKeyIdentifier skiVal = new SubjectKeyIdentifier(DataUtil.stringToByteArray(currentKey));
					System.out.println("Searching for SKI Value: " + DataUtil.byteArrayToString(skiVal.getEncoded()));
					skiSelector.setSubjectKeyIdentifier(skiVal.getEncoded());
					Collection<? extends Certificate> certsFromSelector = null;
					try {
						certsFromSelector = cstore.getCertificates(skiSelector);
					} catch (CertStoreException e) {
						e.printStackTrace();
					}
					if (certsFromSelector != null && certsFromSelector.size() > 0) {
						X509Certificate signingCA = (X509Certificate) certsFromSelector.toArray()[0];
						System.out.println(signingCA.toString());
					}
				}
			}
			/*
			 * TODO: Purge URLs in persistent JSON map that no longer exist in
			 * the submitted CMS Certs-Only message.
			 */
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void updateMap(String keyIdentifierHexString, String[] newUri) {
		/*
		 * First, check and see if the keyIdentifierHexString is in the map.
		 * 
		 * If not, then add the identifier into the map with the URI array
		 */
		if (crlMap.containsKey(keyIdentifierHexString)) {
			crlMap.put(keyIdentifierHexString, newUri);
			/*
			 * If it does exist, only add *new* urls from the submitted URI
			 * array
			 */
		} else {
			String[] existingUri = crlMap.get(keyIdentifierHexString);
			/*
			 * Make sure the list is not null, if so, update the map with
			 * newURI, otherwise, evaluate
			 */
			if (null != existingUri && existingUri.length > 0) {
				List<String> updatedUriList = new ArrayList<String>();
				for (String uri : existingUri) {
					updatedUriList.add(uri);
				}
				for (String newUriEntry : newUri) {
					if (!updatedUriList.contains(newUriEntry)) {
						updatedUriList.add(newUriEntry);
					}
				}
				crlMap.put(keyIdentifierHexString, updatedUriList.toArray(new String[updatedUriList.size()]));
			} else {
				crlMap.put(keyIdentifierHexString, newUri);
			}
		}
	}

	private static Extensions getExtensions(X509Certificate cert) {
		Set<String> critExt = cert.getCriticalExtensionOIDs();
		Set<String> nonCritExt = cert.getNonCriticalExtensionOIDs();
		Set<Extension> extensions = new HashSet<Extension>();
		for (String oidStr : critExt) {
			ASN1ObjectIdentifier extnId = new ASN1ObjectIdentifier(oidStr);
			byte[] extBytes = cert.getExtensionValue(oidStr);
			extensions.add(new Extension(extnId, true, ASN1OctetString.getInstance(extBytes)));
		}
		for (String oidStr : nonCritExt) {
			ASN1ObjectIdentifier extnId = new ASN1ObjectIdentifier(oidStr);
			byte[] extBytes = cert.getExtensionValue(oidStr);
			extensions.add(new Extension(extnId, false, ASN1OctetString.getInstance(extBytes)));
		}
		Extension[] extArr = new Extension[critExt.size() + nonCritExt.size()];
		return new Extensions(extensions.toArray(extArr));
	}

	private static String[] getCdpUris(X509Certificate cert, String protocol) {
		ArrayList<String> uris = new ArrayList<String>();
		Extensions exts = getExtensions(cert);
		DistributionPoint[] dps = null;
		Extension cdpExt = null;
		if ((cdpExt = exts.getExtension(Extension.cRLDistributionPoints)) != null) {
			CRLDistPoint cdp = CRLDistPoint.getInstance((ASN1Sequence) cdpExt.getParsedValue());
			dps = cdp.getDistributionPoints();
			for (DistributionPoint dp : dps) {
				GeneralNames gNames = null;
				if ((gNames = dp.getCRLIssuer()) != null) {
					GeneralName[] gns = gNames.getNames();
					for (GeneralName gn : gns) {
						if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
							URI thisURI = null;
							try {
								thisURI = new URI(gn.getName().toString());
							} catch (URISyntaxException e) {
								/*
								 * We will swallow this exception for now, and
								 * simply not add it is thisURI is null
								 */
							}
							if (thisURI != null && thisURI.getScheme().toLowerCase().startsWith(protocol)) {
								uris.add(thisURI.toString());
							}
						}
					}
				}
				DistributionPointName dpn = null;
				if ((dpn = dp.getDistributionPoint()) != null) {
					if (dpn.getType() == DistributionPointName.FULL_NAME) {
						GeneralName[] gns = GeneralNames.getInstance(dpn.getName()).getNames();
						for (GeneralName gn : gns) {
							if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
								URI thisURI = null;
								try {
									thisURI = new URI(gn.getName().toString());
								} catch (URISyntaxException e) {
									/*
									 * We will swallow this exception for now,
									 * and simply not add it is thisURI is null
									 */
								}
								if (null != thisURI && null != thisURI.getScheme()
										&& thisURI.getScheme().toLowerCase().startsWith(protocol)) {
									uris.add(thisURI.toString());
								}
							}
						}
					}
				}
			}
		}
		return uris.toArray(new String[uris.size()]);
	}

	private static final int BUFFER_SIZE = 4096;

	/**
	 * Downloads a file from a URL
	 * 
	 * @param uri
	 *            HTTP URL of the file to be downloaded
	 * @param saveDir
	 *            path of the directory to save the file
	 * @throws IOException
	 */
	public static byte[] downloadCRL(URI uri) {
		int responseCode = 0;
		HttpURLConnection httpConn = null;
		try {
			httpConn = (HttpURLConnection) uri.toURL().openConnection();
			responseCode = httpConn.getResponseCode();
			/*
			 * always check HTTP response code first
			 */
			if (responseCode == HttpURLConnection.HTTP_OK) {
				String contentType = httpConn.getContentType();
				int contentLength = httpConn.getContentLength();

				System.out.println("Content-Type = " + contentType);
				System.out.println("Content-Length = " + contentLength);

				/*
				 * opens input stream from the HTTP connection
				 */
				InputStream inputStream = httpConn.getInputStream();

				/*
				 * opens an output stream to create byte[]
				 */
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

				int bytesRead = -1;
				byte[] buffer = new byte[BUFFER_SIZE];
				while ((bytesRead = inputStream.read(buffer)) != -1) {
					outputStream.write(buffer, 0, bytesRead);
				}

				outputStream.close();
				inputStream.close();
				System.out.println("File downloaded");
				httpConn.disconnect();
				return outputStream.toByteArray();
			} else {
				System.out.println("No file to download. Server replied HTTP code: " + responseCode);
				httpConn.disconnect();
				return null;
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}

	}

}
