/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.selector;

import de.rub.nds.modifiablevariable.util.DataConverter;

/**
 * Enumeration of default configuration filter profiles providing various levels of feature
 * reduction for TLS configurations. Each profile defines a set of filters to apply, ranging from
 * unfiltered to extremely reduced feature sets for cipher suites, named groups, and signature
 * algorithms.
 */
public enum DefaultConfigProfile implements ConfigFilterProfile {
    UNFILTERED(),

    SLIGHTLY_REDUCED_CIPHERSUITES(
            ConfigFilterType.CIPHERSUITE_UNNEGOTIABLE,
            ConfigFilterType.CIPHERSUITE_UNOFFICIAL,
            ConfigFilterType.CIPHERSUITE_GREASE),
    MODERATELY_REDUCED_CIPHERSUITES(
            SLIGHTLY_REDUCED_CIPHERSUITES.getConfigFilterTypes(),
            ConfigFilterType.CIPHERSUITE_KRB5,
            ConfigFilterType.CIPHERSUITE_ECCPWD),
    HIGHLY_REDUCED_CIPHERSUITES(
            MODERATELY_REDUCED_CIPHERSUITES.getConfigFilterTypes(),
            ConfigFilterType.CIPHERSUITE_ANON,
            ConfigFilterType.CIPHERSUITE_GOST,
            ConfigFilterType.CIPHERSUITE_EXPORT,
            ConfigFilterType.CIPHERSUITE_PSK,
            ConfigFilterType.CIPHERSUITE_SRP,
            ConfigFilterType.CIPHERSUITE_ARIA,
            ConfigFilterType.CIPHERSUITE_CAMELLIA),
    EXTREMELY_REDUCED_CIPHERSUITES(
            HIGHLY_REDUCED_CIPHERSUITES.getConfigFilterTypes(),
            ConfigFilterType.CIPHERSUITE_DES,
            ConfigFilterType.CIPHERSUITE_RC4,
            ConfigFilterType.CIPHERSUITE_NULL),

    SLIGHTLY_REDUCED_NAMED_GROUPS(ConfigFilterType.NAMEDGROUP_GREASE),
    MODERATELY_REDUCED_NAMED_GROUPS(
            SLIGHTLY_REDUCED_NAMED_GROUPS.getConfigFilterTypes(), ConfigFilterType.NAMEDGROUP_SECT),
    HIGHLY_REDUCED_NAMED_GROUPS(
            MODERATELY_REDUCED_NAMED_GROUPS.getConfigFilterTypes(),
            ConfigFilterType.NAMEDGROUP_DEPRECATED),

    SLIGHTLY_REDUCED_SIGNATUREALGORITHMS(ConfigFilterType.SIGNATUREALGORITHM_GREASE),
    MODERATELY_REDUCED_SIGNATUREALGORITHMS(
            SLIGHTLY_REDUCED_SIGNATUREALGORITHMS.getConfigFilterTypes(),
            ConfigFilterType.SIGNATUREALGORITHM_ANON,
            ConfigFilterType.SIGNATUREALGORITHM_GOST),
    HIGHLY_REDUCED_SIGNATUREALGORITHMS(
            MODERATELY_REDUCED_SIGNATUREALGORITHMS.getConfigFilterTypes(),
            ConfigFilterType.SIGNATUREALGORITHM_DEPRECATED,
            ConfigFilterType.SIGNATUREALGORITHM_DSA),
    EXTREMELY_REDUCED_SIGNATUREALGORITHMS(
            HIGHLY_REDUCED_SIGNATUREALGORITHMS.getConfigFilterTypes(),
            ConfigFilterType.SIGNATUREALGORITHM_RSA_PSS_PSS,
            ConfigFilterType.SIGNATUREALGORITHM_ED),

    RICH_TLS_13(),
    CLEAN_NAMED_GROUPS_TLS_13(ConfigFilterType.NAMEDGROUP_DEPRECATED),
    CLEAN_SIGNATUREALGORITHMS_TLS_13(ConfigFilterType.SIGNATUREALGORITHM_TLS13),
    CLEAN_TLS_13(
            DataConverter.concatenate(
                    CLEAN_NAMED_GROUPS_TLS_13.getConfigFilterTypes(),
                    CLEAN_SIGNATUREALGORITHMS_TLS_13.getConfigFilterTypes()));

    private final ConfigFilterType[] configFilterTypes;

    private DefaultConfigProfile(ConfigFilterType... configFilterTypes) {
        this.configFilterTypes = configFilterTypes;
    }

    private DefaultConfigProfile(
            ConfigFilterType[] previousFilters, ConfigFilterType... configFilterTypes) {
        this.configFilterTypes = DataConverter.concatenate(previousFilters, configFilterTypes);
    }

    @Override
    public ConfigFilterType[] getConfigFilterTypes() {
        return configFilterTypes;
    }

    @Override
    public String getIdentifier() {
        return this.name();
    }

    /**
     * Returns an array of configuration profiles suitable for TLS 1.2 and earlier versions. These
     * profiles provide various levels of feature reduction for testing compatibility.
     *
     * @return array of DefaultConfigProfile enums for TLS 1.2 and earlier versions
     */
    public static DefaultConfigProfile[] getTls12ConfigProfiles() {
        return new DefaultConfigProfile[] {
            UNFILTERED,
            SLIGHTLY_REDUCED_CIPHERSUITES,
            MODERATELY_REDUCED_CIPHERSUITES,
            HIGHLY_REDUCED_CIPHERSUITES,
            EXTREMELY_REDUCED_CIPHERSUITES,
            SLIGHTLY_REDUCED_NAMED_GROUPS,
            MODERATELY_REDUCED_NAMED_GROUPS,
            HIGHLY_REDUCED_NAMED_GROUPS,
            SLIGHTLY_REDUCED_SIGNATUREALGORITHMS,
            MODERATELY_REDUCED_SIGNATUREALGORITHMS,
            HIGHLY_REDUCED_SIGNATUREALGORITHMS,
            EXTREMELY_REDUCED_SIGNATUREALGORITHMS
        };
    }

    /**
     * Returns an array of configuration profiles suitable for TLS 1.3. These profiles include both
     * rich configurations and clean configurations with deprecated features removed.
     *
     * @return array of DefaultConfigProfile enums for TLS 1.3
     */
    public static DefaultConfigProfile[] getTls13ConfigProfiles() {
        return new DefaultConfigProfile[] {
            RICH_TLS_13,
            SLIGHTLY_REDUCED_NAMED_GROUPS,
            MODERATELY_REDUCED_NAMED_GROUPS,
            CLEAN_NAMED_GROUPS_TLS_13,
            CLEAN_SIGNATUREALGORITHMS_TLS_13,
            CLEAN_TLS_13
        };
    }
}
