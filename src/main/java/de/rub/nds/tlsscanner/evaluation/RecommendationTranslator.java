/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.evaluation;

/**
 *
 * @author ic0ns
 */
public class RecommendationTranslator {

    private RecommendationTranslator() {
    }

    public static String getRecommendation(InfluencerConstant constant) {
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
            case NO_NULL_CIPHERS:
                return "Disable NULL ciphersuites";
            case NO_FORTEZZA:
                return "Disable FORTEZZA ciphersuites";
            case NO_EXPORT:
                return "Disable EXPORT ciphersuites";
            case NO_ANON:
                return "Disable ANON ciphersuites";
            case NO_DES:
                return "Disable DES ciphersuites";
            case NO_IDEA:
                return "Disable IDEA ciphersuites";
            case NO_RC2:
                return "Disable RC2 ciphersuites";
            case NO_RC4:
                return "Disable RC4 ciphersuites";
            case NO_CBC:
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
            case NO_TLS_COMPRESSION:
                return "Disable TLS-Compression";
            case NO_VERSION_INTOLERANCES:
            case NO_CIPHERSUITE_INTOLERANCES:
            case NO_EXTENSION_INTOLERANCES:
            case NO_CIPHERSUITE_LENGTH_INTOLERANCES:
            case NO_COMPRESSION_INTOLERANCES:
            case NO_ALPN_INTOLERANCES:
            case NO_CLIENTHELLO_LENGTH_INTOLERANCES:
            case NO_EMPTY_LAST_EXTENSION_INTOLERANCES:
            case NO_SIG_HASH_ALGORITHM_INTOLERANCES:
            case NO_BIG_CLIENT_HELLO_INTOLERANCES:
            case NO_SECOND_CIPHERSUITE_BYTE_BUG:
            case NO_IGNORES_OFFERED_CIPHERSUITES:
            case NO_REFLECTS_OFFERED_CIPHERSUITES:
            case NO_IGNORES_OFFERED_NAMEDGROUPS:
            case NO_IGNORES_OFFERED_SIG_HASH_ALGOS:
                return constant.name();
            case NO_BLEICHENBACHER:
                return "Patch your implementation. It is vulnerable for the Bleichenbacher attack!";
            case NO_PADDINGORACLE:
                return "Patch your implementation. It is vulnerable for the PaddingOracle attack!";
            case NO_HTTP_COMPRESSION:
                return "Disable HTTP Compression";
            case NO_INVALID_CURVE:
                return "Patch your implementation. It is vulnerable for the InvalidCurve attack!";
            case NO_INVALID_CURVE_EPHEMERAL:
                return "Patch your implementation. It is vulnerable for the InvalidCurve(ephemeral) attack!";
            case NO_INVALID_CURVE_EPHEMERAL_WITH_REUSE:
                return "Patch your implementation. It is vulnerable for the InvalidCurve(ephemeral) attack and it reuses EC keys!";
            case NO_POODLE:
                return "Disable SSLv3+CBC Ciphersuites. You are vulnerable to the Poodle attack!";
            case NO_TLS_POODLE:
                return "Patch your implementation. It is vulnerable for the TLS-Poodle attack!";
            case NO_64_BIT_CIPHERSUIET:
                return "Disable 64bit Ciphersuites!";
            case NO_DROWN:
                return "Disable SSLv2. You are vulnerable to the DROWN attack!";
            case NO_HEARTBLEED:
                return "Patch your implementation. It is vulnerable for the Heartbleed attack!";
            case NO_EARLY_CCS:
                return "Patch your implementation. It is vulnerable for the EarlyCCS attack!";
            case NO_MISSING_CHECKS_MAC_APPDATA:
                return "Patch your implementation. Your implementation is not checking MAC's in ApplicationData correctly";
            case NO_MISSING_CHECKS_MAC_FINISHED:
                return "Patch your implementation. Your implementation is not checking MAC's in the FinishedMessage correctly";
            case NO_MISSING_CHECKS_VERIFY_DATA:
                return "Patch your implementation. Your implementation is not the VerifyData in the FinishedMessage correctly";
            case NO_CERTIFICATE_ISSUES:
                return "There are certificate chain issues";
            case NO_INSECURE_RENEGOTIATION:
                return "Disable Insecure Renegotiation";
            case NO_RENEGOTIATION:
                return "Disable RenegotiationCompletly";
            case SUPPORT_HSTS:
                return "Enable HSTS";
            case SUPPORT_HPKP_REPORTING:
                return "Enable HPKP (Reporting)";
            case NO_WEAK_RANDOMNESS:
                return "Patch your implementation. Your implementation is using weak Randomness";
            case NO_EC_PUBLICKEY_REUSE:
                return "Do not reuse EC PublicKeys";
            case NO_DH_PUBLICKEY_REUSE:
                return "Do not reuse Dh PublicKeys";
            case NO_COMMON_DH_PRIMES:
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
