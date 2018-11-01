package com.fkrone.likensing.client;

import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Handles licensing.
 */
public class LicenseChecker {

    private static LicenseChecker licenseCheckerInstance;
    private static Map<String, LicenseData> licensedData = new HashMap<>();
    private PublicKey publicKey;

    /**
     * Initialize the license checker with the provided public key.
     *
     * @param publicKey the public key used to check licenses
     */
    private LicenseChecker(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Returns the current active checker instance.
     * <p>
     * The license checker has to initialized fist by {@link #initLicenseChecker(String)}
     *
     * @return the current active checker instance
     */
    public static LicenseChecker getChecker() {
        if (licenseCheckerInstance == null) {
            throw new IllegalStateException("Initialize the checker with a public key first.");
        }
        return licenseCheckerInstance;
    }

    /**
     * Initializes the license checker with the given public key.
     *
     * @param publicKey the public key which will used to check licenses
     * @throws NoSuchAlgorithmException if the signature algorithm is not available
     * @throws InvalidKeyException      if the public key to verify the license is invalid
     */
    public static void initLicenseChecker(String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (publicKey == null || "".equals(publicKey)) {
            throw new IllegalArgumentException("Provide a valid public key");
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpecPb =
                    new X509EncodedKeySpec(Base64.getDecoder().decode(publicKey.getBytes(StandardCharsets.UTF_8)));
            PublicKey parsedPublicKey = keyFactory.generatePublic(keySpecPb);
            // checking if key is valid
            Signature.getInstance("SHA256withRSA").initVerify(parsedPublicKey);
            licenseCheckerInstance = new LicenseChecker(parsedPublicKey);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Provide a valid public key", e);
        }
    }

    /**
     * Imports the given license.
     *
     * @param license the license to import
     * @throws NoSuchAlgorithmException if the signature algorithm is not available
     * @throws InvalidKeyException      if the public key to verify the license is invalid
     * @throws TransformerException     if parsing the license fails
     * @throws SignatureException       if a forged license is found
     * @throws IOException              if parsing the license fails due to internal handling
     */
    public void importLicense(String license)
            throws TransformerException, NoSuchAlgorithmException, InvalidKeyException, IOException,
                   SignatureException {
        if (license == null || "".equals(license)) {
            throw new IllegalArgumentException("Empty license found.");
        }

        LicenseParser licenseParser = new LicenseParser(publicKey);
        LicenseData scopeLicensedData = licenseParser.parseLicense(license);

        licensedData.put(scopeLicensedData.getScopeId(), scopeLicensedData);
    }

    /**
     * Checks whether a license is available for the given
     * scope uid.
     *
     * @param scopeUid the uid of the scope to check
     * @return <tt>true</tt> if a license is available for the given
     * scope uid, <tt>false</tt> otherwise
     */
    public boolean hasLicense(String scopeUid) {
        if (scopeUid == null || "".equals(scopeUid)) {
            throw new IllegalArgumentException("Please provide a valid scope uid");
        }
        return licensedData.containsKey(scopeUid);
    }

    /**
     * Checks if the license for the given scope uid is still valid.
     *
     * @param scopeUid the uid of the scope to check
     * @return <tt>true</tt> if the license is still valid for
     * the scope, <tt>false</tt> otherwise
     */
    public boolean isLicenseStillValid(String scopeUid) {
        if (!hasLicense(scopeUid)) {
            return false;
        }
        LicenseData scopeLicensedData = licensedData.get(scopeUid);
        if (LocalDate.now().isAfter(scopeLicensedData.getValidUntil())) {
            return false;
        }
        return true;
    }

    /**
     * Checks if the given feature is licensed for the given scope uid.
     *
     * @param scopeUid the uid of the scope to check
     * @param feature  the feature to check
     * @return <tt>true</tt> the feature is licensed, <tt>false</tt> otherwise
     */
    public boolean isLicensed(String scopeUid, String feature) {
        if (!isLicenseStillValid(scopeUid)) {
            return false;
        }

        return licensedData.get(scopeUid).getLicensedFeatures().contains(feature);
    }
}
