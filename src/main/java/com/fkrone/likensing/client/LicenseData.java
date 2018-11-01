package com.fkrone.likensing.client;

import java.time.LocalDate;
import java.util.Set;

/**
 * Represents licensed data parsed from a license file.
 */
class LicenseData {

    private String scopeId;
    private Set<String> licensedFeatures;
    private LocalDate validUntil;

    /**
     * Generates a new representation of a license.
     *
     * @param scopeId          the scope uid the licensed data is for
     * @param licensedFeatures set containing the licensed features
     * @param validUntil       the last date the license is valid
     */
    LicenseData(String scopeId, Set<String> licensedFeatures, LocalDate validUntil) {
        this.scopeId = scopeId;
        this.licensedFeatures = licensedFeatures;
        this.validUntil = validUntil;
    }

    String getScopeId() {
        return scopeId;
    }

    Set<String> getLicensedFeatures() {
        return licensedFeatures;
    }

    LocalDate getValidUntil() {
        return validUntil;
    }
}
