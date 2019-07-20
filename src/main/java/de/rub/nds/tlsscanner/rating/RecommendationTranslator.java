/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import de.rub.nds.tlsscanner.report.AnalyzedProperty;

/**
 *
 * @author ic0ns
 */
public class RecommendationTranslator {

    private RecommendationTranslator() {
    }

    public static String getRecommendation(AnalyzedProperty constant) {
        switch (constant) {
            case SUPPORTS_SSL_2:
                return "Disable SSLv2 support";
            case SUPPORTS_SSL_3:
                return "Disable SSlv3 support";
            case SUPPORTS_TLS_1_0:
                return "Consider disabling TLS 1.0";
            case SUPPORTS_TLS_1_3:
                return "Enable TLS 1.3";
            case SUPPORTS_TLS_1_3_DRAFT:
                return "Disable TLS 1.3 draft Versions";
            case SUPPORTS_PFS:
                return "Support perfect forward secure ciphersuites";
            case PREFERS_PFS:
                return "Prefer perfect forward secure ciphersuites";
            case ENFORCES_PFS:
                return "Enforce the usage of perfect forward secure ciphersuites";
            case ENFOCRES_CS_ORDERING:
                return "Enforce the ciphersuite selection (order) server side";
            case SUPPORTS_NULL_CIPHERS:
                return "Disable NULL ciphersuites";
            case SUPPORTS_FORTEZZA:
                return "Disable FORTEZZA ciphersuites";
            case SUPPORTS_EXPORT:
                return "Disable EXPORT ciphersuites";
            case SUPPORTS_ANON:
                return "Disable ANON ciphersuites";
            case SUPPORTS_DES:
                return "Disable DES ciphersuites";
            case SUPPORTS_IDEA:
                return "Disable IDEA ciphersuites";
            case SUPPORTS_RC2:
                return "Disable RC2 ciphersuites";
            case SUPPORTS_RC4:
                return "Disable RC4 ciphersuites";
            case SUPPORTS_CBC:
                return "Disable CBC ciphersuites";
            case SUPPORTS_AEAD:
                return "Support AEAD ciphersuites";
            case SUPPORTS_EXTENDED_MASTER_SECRET:
                return "Support the Extended Mastersecret Extension";
            case SUPPORTS_ENCRYPT_THEN_MAC:
                return "Support the Encrypt Then Mac Extension";
            case SUPPORTS_MONTOGMERY_CURVES:
                return "Support Montgomery Curves (X25519, X448)";
            case SUPPORTS_SESSION_TICKETS:
                return "Support SessionTickets";
            case SUPPORTS_SECURE_RENEGOTIATION_EXTENSION:
                return "Support the Secure Renegotiation Extension";
            case SUPPORTS_TOKENBINDING:
                return "Support Tokenbinding";
            case SUPPORTS_TLS_COMPRESSION:
                return "Disable TLS-Compression";
            case HAS_VERSION_INTOLERANCE:
            case HAS_CIPHERSUITE_INTOLERANCE:
            case HAS_EXTENSION_INTOLERANCE:
            case HAS_CIPHERSUITE_LENGTH_INTOLERANCE:
            case HAS_COMPRESSION_INTOLERANCE:
            case HAS_ALPN_INTOLERANCE:
            case HAS_CLIENT_HELLO_LENGTH_INTOLERANCE:
            case HAS_EMPTY_LAST_EXTENSION_INTOLERANCE:
            case HAS_SIG_HASH_ALGORITHM_INTOLERANCE:
            case HAS_BIG_CLIENT_HELLO_INTOLERANCE:
            case HAS_SECOND_CIPHERSUITE_BYTE_BUG:
            case IGNORES_OFFERED_CIPHERSUITES:
            case REFLECTS_OFFERED_CIPHERSUITES:
            case IGNORES_OFFERED_NAMED_GROUPS:
            case IGNORES_OFFERED_SIG_HASH_ALGOS:
                return constant.name();
            case VULNERABLE_TO_BLEICHENBACHER:
                return "Patch your implementation. It is vulnerable for the Bleichenbacher attack!";
            case VULNERABLE_TO_CBC_PADDING_ORACLE:
                return "Patch your implementation. It is vulnerable for the PaddingOracle attack!";
            case SUPPORTS_HTTP_COMPRESSION:
                return "Disable HTTP Compression";
            case VULNERABLE_TO_INVALID_CURVE:
                return "Patch your implementation. It is vulnerable for the InvalidCurve attack!";
            case VULNERABLE_TO_INVALID_CURVE_EPHEMERAL:
                return "Patch your implementation. It is vulnerable for the InvalidCurve(ephemeral) attack!";
            case VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_WITH_REUSE:
                return "Patch your implementation. It is vulnerable for the InvalidCurve(ephemeral) attack and it reuses EC keys!";
            case VULNERABLE_TO_POODLE:
                return "Disable SSLv3+CBC Ciphersuites. You are vulnerable to the Poodle attack!";
            case VULNERABLE_TO_TLS_POODLE:
                return "Patch your implementation. It is vulnerable for the TLS-Poodle attack!";
            case VULNERABLE_TO_SWEET_32:
                return "Disable 64bit Ciphersuites!";
            case VULNERABLE_TO_DROWN:
                return "Disable SSLv2. You are vulnerable to the DROWN attack!";
            case VULNERABLE_TO_HEARTBLEED:
                return "Patch your implementation. It is vulnerable for the Heartbleed attack!";
            case VULNERABLE_TO_EARLY_CCS:
                return "Patch your implementation. It is vulnerable for the EarlyCCS attack!";
            case MISSES_MAC_APPDATA_CHECKS:
                return "Patch your implementation. Your implementation is not checking MAC's in ApplicationData correctly";
            case MISSES_CHECKS_MAC_FINISHED_CHECKS:
                return "Patch your implementation. Your implementation is not checking MAC's in the FinishedMessage correctly";
            case MISSES_CHECKS_VERIFY_DATA_CHECKS:
                return "Patch your implementation. Your implementation is not the VerifyData in the FinishedMessage correctly";
            case HAS_CERTIFICATE_ISSUES:
                return "There are certificate chain issues";
            case SUPPORTS_INSECURE_RENEGOTIATION:
                return "Disable Insecure Renegotiation";
            case SUPPORTS_RENEGOTIATION:
                return "Disable RenegotiationCompletly";
            case SUPPORTS_HSTS:
                return "Enable HSTS";
            case SUPPORTS_HPKP_REPORTING:
                return "Enable HPKP (Reporting)";
            case HAS_WEAK_RANDOMNESS:
                return "Patch your implementation. Your implementation is using weak Randomness";
            case REUSES_EC_PUBLICKEY:
                return "Do not reuse EC PublicKeys";
            case REUSES_DH_PUBLICKEY:
                return "Do not reuse Dh PublicKeys";
            case SUPPORTS_COMMON_DH_PRIMES:
                return "Do not use Common DH Primes";
            case SUPPORTS_PRIME_MODULI:
                return "You must use Prime Moduli!!!";
            case SUPPORTS_SAFEPRIME_MODULI:
                return "You should use Safeprime Moduli";
            default:
                return "UNKNOWN";
        }
    }
}
