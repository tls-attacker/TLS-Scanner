/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

/**
 *
 * @author ic0ns
 */
public class RecommendationTranslator {

    private RecommendationTranslator() {
    }

    public static String getRecommendation(AnalyzedProperty constant) {
        switch (constant) {
            case SSL_2:
                return "Disable SSLv2 support";
            case SSL_3:
                return "Disable SSlv3 support";
            case TLS_1_0:
                return "Consider disabling TLS 1.0";
            case TLS_1_3:
                return "Enable TLS 1.3";
            case TLS_1_3_DRAFT:
                return "Disable TLS 1.3 draft Versions";
            case SUPPORT_PFS:
                return "Support perfect forward secure ciphersuites";
            case PREFER_PFS:
                return "Prefer perfect forward secure ciphersuites";
            case ENFORCE_PFS:
                return "Enforce the usage of perfect forward secure ciphersuites";
            case ENFOCRE_CS_ORDERING:
                return "Enforce the ciphersuite selection (order) server side";
            case NULL_CIPHERS:
                return "Disable NULL ciphersuites";
            case FORTEZZA:
                return "Disable FORTEZZA ciphersuites";
            case EXPORT:
                return "Disable EXPORT ciphersuites";
            case ANON:
                return "Disable ANON ciphersuites";
            case DES:
                return "Disable DES ciphersuites";
            case IDEA:
                return "Disable IDEA ciphersuites";
            case RC2:
                return "Disable RC2 ciphersuites";
            case RC4:
                return "Disable RC4 ciphersuites";
            case CBC:
                return "Disable CBC ciphersuites";
            case SUPPORT_AEAD:
                return "Support AEAD ciphersuites";
            case SUPPORT_EXTENDED_MASTER_SECRET:
                return "Support the Extended Mastersecret Extension";
            case SUPPORT_ENCRYPT_THEN_MAC:
                return "Support the Encrypt Then Mac Extension";
            case SUPPORT_MONTOGMERY_CURVES:
                return "Support Montgomery Curves (X25519, X448)";
            case SUPPORT_SESSION_TICKETS:
                return "Support SessionTickets";
            case SUPPORT_SECURE_RENEGOTIATION_EXTENSION:
                return "Support the Secure Renegotiation Extension";
            case SUPPORT_TOKENBINDING:
                return "Support Tokenbinding";
            case TLS_COMPRESSION:
                return "Disable TLS-Compression";
            case VERSION_INTOLERANCES:
            case CIPHERSUITE_INTOLERANCES:
            case EXTENSION_INTOLERANCES:
            case CIPHERSUITE_LENGTH_INTOLERANCES:
            case COMPRESSION_INTOLERANCES:
            case ALPN_INTOLERANCES:
            case CLIENTHELLO_LENGTH_INTOLERANCES:
            case EMPTY_LAST_EXTENSION_INTOLERANCES:
            case SIG_HASH_ALGORITHM_INTOLERANCES:
            case BIG_CLIENT_HELLO_INTOLERANCES:
            case SECOND_CIPHERSUITE_BYTE_BUG:
            case IGNORES_OFFERED_CIPHERSUITES:
            case REFLECTS_OFFERED_CIPHERSUITES:
            case IGNORES_OFFERED_NAMEDGROUPS:
            case IGNORES_OFFERED_SIG_HASH_ALGOS:
                return constant.name();
            case BLEICHENBACHER:
                return "Patch your implementation. It is vulnerable for the Bleichenbacher attack!";
            case CBC_PADDING_ORACLE:
                return "Patch your implementation. It is vulnerable for the PaddingOracle attack!";
            case HTTP_COMPRESSION:
                return "Disable HTTP Compression";
            case INVALID_CURVE:
                return "Patch your implementation. It is vulnerable for the InvalidCurve attack!";
            case INVALID_CURVE_EPHEMERAL:
                return "Patch your implementation. It is vulnerable for the InvalidCurve(ephemeral) attack!";
            case INVALID_CURVE_EPHEMERAL_WITH_REUSE:
                return "Patch your implementation. It is vulnerable for the InvalidCurve(ephemeral) attack and it reuses EC keys!";
            case POODLE:
                return "Disable SSLv3+CBC Ciphersuites. You are vulnerable to the Poodle attack!";
            case TLS_POODLE:
                return "Patch your implementation. It is vulnerable for the TLS-Poodle attack!";
            case SHORT_64_BIT_CIPHERSUITE:
                return "Disable 64bit Ciphersuites!";
            case DROWN:
                return "Disable SSLv2. You are vulnerable to the DROWN attack!";
            case HEARTBLEED:
                return "Patch your implementation. It is vulnerable for the Heartbleed attack!";
            case EARLY_CCS:
                return "Patch your implementation. It is vulnerable for the EarlyCCS attack!";
            case MISSING_CHECKS_MAC_APPDATA:
                return "Patch your implementation. Your implementation is not checking MAC's in ApplicationData correctly";
            case MISSING_CHECKS_MAC_FINISHED:
                return "Patch your implementation. Your implementation is not checking MAC's in the FinishedMessage correctly";
            case MISSING_CHECKS_VERIFY_DATA:
                return "Patch your implementation. Your implementation is not the VerifyData in the FinishedMessage correctly";
            case CERTIFICATE_ISSUES:
                return "There are certificate chain issues";
            case INSECURE_RENEGOTIATION:
                return "Disable Insecure Renegotiation";
            case RENEGOTIATION:
                return "Disable RenegotiationCompletly";
            case SUPPORT_HSTS:
                return "Enable HSTS";
            case SUPPORT_HPKP_REPORTING:
                return "Enable HPKP (Reporting)";
            case WEAK_RANDOMNESS:
                return "Patch your implementation. Your implementation is using weak Randomness";
            case EC_PUBLICKEY_REUSE:
                return "Do not reuse EC PublicKeys";
            case DH_PUBLICKEY_REUSE:
                return "Do not reuse Dh PublicKeys";
            case COMMON_DH_PRIMES:
                return "Do not use Common DH Primes";
            case SUPPORT_PRIME_MODULI:
                return "You must use Prime Moduli!!!";
            case SUPPORT_SAFEPRIME_MODULI:
                return "You should use Safeprime Moduli";
            default:
                return "UNKNOWN";
        }
    }
}
