/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.selector;

/**
 * Enumeration of configuration filter types used to exclude specific TLS features from
 * configurations.
 */
public enum ConfigFilterType {
    CIPHERSUITE_UNNEGOTIABLE,
    CIPHERSUITE_UNOFFICIAL,
    CIPHERSUITE_GREASE,
    CIPHERSUITE_KRB5,
    CIPHERSUITE_GOST,
    CIPHERSUITE_PSK,
    CIPHERSUITE_SRP,
    CIPHERSUITE_ECCPWD,
    CIPHERSUITE_ANON,
    CIPHERSUITE_ARIA,
    CIPHERSUITE_CAMELLIA,
    CIPHERSUITE_EXPORT,
    CIPHERSUITE_DES,
    CIPHERSUITE_RC4,
    CIPHERSUITE_NULL,

    NAMEDGROUP_GREASE,
    NAMEDGROUP_DEPRECATED,
    NAMEDGROUP_SECT,

    SIGNATUREALGORITHM_GREASE,
    SIGNATUREALGORITHM_ANON,
    SIGNATUREALGORITHM_DSA,
    SIGNATUREALGORITHM_GOST,
    SIGNATUREALGORITHM_ED,
    SIGNATUREALGORITHM_RSA_PSS_PSS,
    SIGNATUREALGORITHM_DEPRECATED,
    SIGNATUREALGORITHM_TLS13;

    /**
     * Checks whether this filter type applies to cipher suites.
     *
     * @return true if this is a cipher suite filter, false otherwise
     */
    public boolean isCipherSuiteFilter() {
        return this.name().contains("CIPHERSUITE");
    }

    /**
     * Checks whether this filter type applies to named groups.
     *
     * @return true if this is a named group filter, false otherwise
     */
    public boolean isNamedGroupFilter() {
        return this.name().contains("NAMEDGROUP");
    }

    /**
     * Checks whether this filter type applies to signature algorithms.
     *
     * @return true if this is a signature algorithm filter, false otherwise
     */
    public boolean isSignatureAlgorithmFilter() {
        return this.name().contains("SIGNATUREALGORITHM");
    }
}
