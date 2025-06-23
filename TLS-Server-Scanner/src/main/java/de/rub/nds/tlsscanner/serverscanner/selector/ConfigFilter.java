/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.selector;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Utility class for applying configuration filters to TLS configurations. Provides functionality to
 * filter cipher suites, named groups, and signature algorithms based on specified filter types.
 */
public class ConfigFilter {
    /**
     * Applies a filter profile to the given configuration by modifying its cipher suites, named
     * groups, and signature algorithms according to the specified filter types.
     *
     * @param baseConfig the configuration to be modified
     * @param configFilterTypes array of filter types to apply to the configuration
     * @throws IllegalArgumentException if an undefined filter type is encountered
     */
    public static void applyFilterProfile(Config baseConfig, ConfigFilterType[] configFilterTypes) {
        for (ConfigFilterType filterType : configFilterTypes) {
            if (filterType.isCipherSuiteFilter()) {
                filterCipherSuites(baseConfig, filterType);
            } else if (filterType.isNamedGroupFilter()) {
                filterNamedGroups(baseConfig, filterType);
            } else if (filterType.isSignatureAlgorithmFilter()) {
                filterSignatureAlgorithms(baseConfig, filterType);
            } else {
                throw new IllegalArgumentException("No behavior defined for filter " + filterType);
            }
        }
    }

    private static void filterCipherSuites(Config baseConfig, ConfigFilterType filterType) {
        List<CipherSuite> reducedCipherSuites = baseConfig.getDefaultClientSupportedCipherSuites();
        switch (filterType) {
            case CIPHERSUITE_ANON:
                String anonEnumSubstring =
                        filterType.name().replace("CIPHERSUITE_", "").toLowerCase();
                reducedCipherSuites =
                        reducedCipherSuites.stream()
                                .filter(
                                        cipherSuite ->
                                                !cipherSuite.name().contains(anonEnumSubstring))
                                .collect(Collectors.toList());
                break;
            case CIPHERSUITE_ECCPWD:
            case CIPHERSUITE_EXPORT:
            case CIPHERSUITE_GREASE:
            case CIPHERSUITE_GOST:
            case CIPHERSUITE_KRB5:
            case CIPHERSUITE_PSK:
            case CIPHERSUITE_ARIA:
            case CIPHERSUITE_SRP:
            case CIPHERSUITE_CAMELLIA:
            case CIPHERSUITE_UNOFFICIAL:
            case CIPHERSUITE_DES:
            case CIPHERSUITE_RC4:
            case CIPHERSUITE_NULL:
                String filteredEnumSubstring = filterType.name().replace("CIPHERSUITE_", "");
                reducedCipherSuites =
                        reducedCipherSuites.stream()
                                .filter(
                                        cipherSuite ->
                                                !cipherSuite.name().contains(filteredEnumSubstring))
                                .collect(Collectors.toList());
                break;
            case CIPHERSUITE_UNNEGOTIABLE:
                reducedCipherSuites =
                        reducedCipherSuites.stream()
                                .filter(cipherSuite -> cipherSuite.isRealCipherSuite())
                                .collect(Collectors.toList());
                break;
            default:
                throw new IllegalArgumentException("No behavior defined for filter " + filterType);
        }
        baseConfig.setDefaultClientSupportedCipherSuites(reducedCipherSuites);
    }

    private static void filterNamedGroups(Config baseConfig, ConfigFilterType filterType) {
        List<NamedGroup> reducedNamedGroups = baseConfig.getDefaultClientNamedGroups();
        switch (filterType) {
            case NAMEDGROUP_GREASE:
            case NAMEDGROUP_SECT:
                String filteredEnumSubstring = filterType.name().replace("NAMEDGROUP_", "");
                reducedNamedGroups =
                        reducedNamedGroups.stream()
                                .filter(group -> !group.name().contains(filteredEnumSubstring))
                                .collect(Collectors.toList());
                break;
            case NAMEDGROUP_DEPRECATED:
                reducedNamedGroups =
                        reducedNamedGroups.stream()
                                .filter(NamedGroup::isTls13)
                                .collect(Collectors.toList());
                break;
            default:
                throw new IllegalArgumentException("No behavior defined for filter " + filterType);
        }
        baseConfig.setDefaultClientNamedGroups(reducedNamedGroups);
    }

    private static void filterSignatureAlgorithms(Config baseConfig, ConfigFilterType filterType) {
        List<SignatureAndHashAlgorithm> reducedSignatureAlgorithms =
                baseConfig.getDefaultClientSupportedSignatureAndHashAlgorithms();
        switch (filterType) {
            case SIGNATUREALGORITHM_DEPRECATED:
                reducedSignatureAlgorithms =
                        reducedSignatureAlgorithms.stream()
                                .filter(
                                        algo ->
                                                !algo.name().contains("NONE")
                                                        && !algo.name().contains("MD5")
                                                        && !algo.name().contains("SHA1")
                                                        && !algo.name().contains("SHA224"))
                                .collect(Collectors.toList());
                break;
            case SIGNATUREALGORITHM_RSA_PSS_PSS:
            case SIGNATUREALGORITHM_ED:
            case SIGNATUREALGORITHM_GOST:
            case SIGNATUREALGORITHM_ANON:
            case SIGNATUREALGORITHM_DSA:
            case SIGNATUREALGORITHM_GREASE:
                String filteredEnumSubstring = filterType.name().replace("SIGNATUREALGORITHM_", "");
                reducedSignatureAlgorithms =
                        reducedSignatureAlgorithms.stream()
                                .filter(algo -> !algo.name().contains(filteredEnumSubstring))
                                .collect(Collectors.toList());
                break;
            case SIGNATUREALGORITHM_TLS13:
                reducedSignatureAlgorithms =
                        reducedSignatureAlgorithms.stream()
                                .filter(
                                        SignatureAndHashAlgorithm
                                                        .getTls13SignatureAndHashAlgorithms()
                                                ::contains)
                                .collect(Collectors.toList());
                break;
            default:
                throw new IllegalArgumentException("No behavior defined for filter " + filterType);
        }
        baseConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(reducedSignatureAlgorithms);
    }
}
