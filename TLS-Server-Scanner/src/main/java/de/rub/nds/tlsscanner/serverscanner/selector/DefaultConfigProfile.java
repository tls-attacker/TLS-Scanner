/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.selector;

import de.rub.nds.modifiablevariable.util.ArrayConverter;

public enum DefaultConfigProfile implements ConfigFilterProfile {

    UNFILTERED(),

    SLIGHTLY_REDUCED_CIPHERSUITES(ConfigFilterType.CIPHERSUITE_UNNEGOTIABLE, ConfigFilterType.CIPHERSUITE_UNOFFICIAL,
        ConfigFilterType.CIPHERSUITE_GREASE),
    MODERATELY_REDUCED_CIPHERSUITES(SLIGHTLY_REDUCED_CIPHERSUITES.getConfigFilterTypes(),
        ConfigFilterType.CIPHERSUITE_KRB5, ConfigFilterType.CIPHERSUITE_ECCPWD),
    HIGHLY_REDUCED_CIPHERSUITES(MODERATELY_REDUCED_CIPHERSUITES.getConfigFilterTypes(),
        ConfigFilterType.CIPHERSUITE_ANON, ConfigFilterType.CIPHERSUITE_GOST, ConfigFilterType.CIPHERSUITE_EXPORT,
        ConfigFilterType.CIPHERSUITE_PSK, ConfigFilterType.CIPHERSUITE_SRP, ConfigFilterType.CIPHERSUITE_ARIA,
        ConfigFilterType.CIPHERSUITE_CAMELLIA),
    EXTREMELY_REDUCED_CIPHERSUITES(HIGHLY_REDUCED_CIPHERSUITES.getConfigFilterTypes(), ConfigFilterType.CIPHERSUITE_DES,
        ConfigFilterType.CIPHERSUITE_RC4, ConfigFilterType.CIPHERSUITE_NULL),

    SLIGHTLY_REDUCED_NAMEDGROUPS(ConfigFilterType.NAMEDGROUP_GREASE),
    MODERATELY_REDUCED_NAMEDGROUPS(SLIGHTLY_REDUCED_NAMEDGROUPS.getConfigFilterTypes(),
        ConfigFilterType.NAMEDGROUP_SECT),
    HIGHLY_REDUCED_NAMEDGROUPS(MODERATELY_REDUCED_NAMEDGROUPS.getConfigFilterTypes(),
        ConfigFilterType.NAMEDGROUP_DEPRECATED),

    SLIGHTLY_REDUCED_SIGNATUREALGORITHMS(ConfigFilterType.SIGNATUREALGORITHM_GREASE),
    MODERATELY_REDUCED_SIGNATUREALGORITHMS(SLIGHTLY_REDUCED_SIGNATUREALGORITHMS.getConfigFilterTypes(),
        ConfigFilterType.SIGNATUREALGORITHM_ANON, ConfigFilterType.SIGNATUREALGORITHM_GOST),
    HIGHLY_REDUCED_SIGNATUREALGORITHMS(MODERATELY_REDUCED_SIGNATUREALGORITHMS.getConfigFilterTypes(),
        ConfigFilterType.SIGNATUREALGORITHM_DEPRECATED, ConfigFilterType.SIGNATUREALGORITHM_DSA),
    EXTREMELY_REDUCED_SIGNATUREALGORITHMS(HIGHLY_REDUCED_SIGNATUREALGORITHMS.getConfigFilterTypes(),
        ConfigFilterType.SIGNATUREALGORITHM_RSA_PSS_PSS, ConfigFilterType.SIGNATUREALGORITHM_ED),

    RICH_TLS_13(),
    CLEAN_NAMEDGROUPS_TLS_13(ConfigFilterType.NAMEDGROUP_DEPRECATED),
    CLEAN_SIGNATUREALGORITHMS_TLS_13(ConfigFilterType.SIGNATUREALGORITHM_TLS13),
    CLEAN_TLS_13(ArrayConverter.concatenate(CLEAN_NAMEDGROUPS_TLS_13.getConfigFilterTypes(),
        CLEAN_SIGNATUREALGORITHMS_TLS_13.getConfigFilterTypes()));

    private final ConfigFilterType[] configFilterTypes;

    private DefaultConfigProfile(ConfigFilterType... configFilterTypes) {
        this.configFilterTypes = configFilterTypes;
    }

    private DefaultConfigProfile(ConfigFilterType[] previousFilters, ConfigFilterType... configFilterTypes) {
        this.configFilterTypes = ArrayConverter.concatenate(previousFilters, configFilterTypes);
    }

    @Override
    public ConfigFilterType[] getConfigFilterTypes() {
        return configFilterTypes;
    }

    @Override
    public String getIdentifier() {
        return this.name();
    }

    public static DefaultConfigProfile[] getTls12ConfigProfiles() {
        return new DefaultConfigProfile[] { UNFILTERED, SLIGHTLY_REDUCED_CIPHERSUITES, MODERATELY_REDUCED_CIPHERSUITES,
            HIGHLY_REDUCED_CIPHERSUITES, EXTREMELY_REDUCED_CIPHERSUITES, SLIGHTLY_REDUCED_NAMEDGROUPS,
            MODERATELY_REDUCED_NAMEDGROUPS, HIGHLY_REDUCED_NAMEDGROUPS, SLIGHTLY_REDUCED_SIGNATUREALGORITHMS,
            MODERATELY_REDUCED_SIGNATUREALGORITHMS, HIGHLY_REDUCED_SIGNATUREALGORITHMS,
            EXTREMELY_REDUCED_SIGNATUREALGORITHMS };
    }

    public static DefaultConfigProfile[] getTls13ConfigProfiles() {
        return new DefaultConfigProfile[] { RICH_TLS_13, SLIGHTLY_REDUCED_NAMEDGROUPS, MODERATELY_REDUCED_NAMEDGROUPS,
            CLEAN_NAMEDGROUPS_TLS_13, CLEAN_SIGNATUREALGORITHMS_TLS_13, CLEAN_TLS_13 };
    }

}
