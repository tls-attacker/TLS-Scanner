/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.selector;

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

    public boolean isCipherSuiteFilter() {
        return this.name().contains("CIPHERSUITE");
    }

    public boolean isNamedGroupFilter() {
        return this.name().contains("NAMEDGROUP");
    }

    public boolean isSignatureAlgorithmFilter() {
        return this.name().contains("SIGNATUREALGORITHM");
    }
}
