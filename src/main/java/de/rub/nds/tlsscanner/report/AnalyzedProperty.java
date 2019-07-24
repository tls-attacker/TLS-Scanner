/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

public enum AnalyzedProperty {

    SUPPORTS_SSL_2(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_SSL_3(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_0(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_1(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_2(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_14(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_15(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_16(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_17(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_18(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_19(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_20(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_21(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_22(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_23(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_24(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_25(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_26(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_27(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_28(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_DTLS_1_0(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_DTLS_1_2(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_DTLS_1_3(AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_PFS(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_NULL_CIPHERS(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_FORTEZZA(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_EXPORT(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_ANON(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_DES(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_3DES(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_SEED(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_IDEA(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_RC2(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_RC4(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_CBC(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_AEAD(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_POST_QUANTUM(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_ONLY_PFS(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_AES(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_CAMELLIA(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_ARIA(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_CHACHA(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_RSA(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_DH(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_ECDH(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_STATIC_ECDH(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_GOST(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_SRP(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_KERBEROS(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_PSK_PLAIN(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_PSK_RSA(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_PSK_DHE(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_PSK_ECDHE(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_NEWHOPE(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_ECMQV(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_STREAM_CIPHERS(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_BLOCK_CIPHERS(AnalyzedPropertyCategory.SUPPORTED_CIPHERSUITS),
    SUPPORTS_EXTENDED_MASTER_SECRET(AnalyzedPropertyCategory.EXTENSIONS),
    SUPPORTS_ENCRYPT_THEN_MAC(AnalyzedPropertyCategory.EXTENSIONS),
    SUPPORTS_TOKENBINDING(AnalyzedPropertyCategory.EXTENSIONS),
    SUPPORTS_MONTOGMERY_CURVES(AnalyzedPropertyCategory.EC), // ?

    SUPPORTS_SESSION_TICKETS(AnalyzedPropertyCategory.SESSION_RESUMPTION),
    SUPPORTS_SESSION_IDS(AnalyzedPropertyCategory.SESSION_RESUMPTION),
    SUPPORTS_SESSION_TICKETS_ROTATED(AnalyzedPropertyCategory.SESSION_RESUMPTION),
    SUPPORTS_SECURE_RENEGOTIATION_EXTENSION(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION_EXTENSION(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_TLS_FALLBACK_SCSV(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_TLS_COMPRESSION(AnalyzedPropertyCategory.COMPRESSION), // ?

    SUPPORTS_COMMON_DH_PRIMES(AnalyzedPropertyCategory.FFDHE),
    SUPPORTS_PRIME_MODULI(AnalyzedPropertyCategory.FFDHE),
    SUPPORTS_SAFEPRIME_MODULI(AnalyzedPropertyCategory.FFDHE),
    SUPPORTS_INSECURE_RENEGOTIATION(AnalyzedPropertyCategory.RENEGOTIATION), // ?
    SUPPORTS_RENEGOTIATION(AnalyzedPropertyCategory.RENEGOTIATION), // ?

    SUPPORTS_HTTPS(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HSTS(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HSTS_PRELOADING(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HPKP(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HPKP_REPORTING(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HTTP_COMPRESSION(AnalyzedPropertyCategory.HTTPS_HEADERS), // ?

    PREFERS_PFS(AnalyzedPropertyCategory.BEST_PRACTICE),
    ENFORCES_PFS(AnalyzedPropertyCategory.BEST_PRACTICE), // ?
    ENFOCRES_CS_ORDERING(AnalyzedPropertyCategory.BEST_PRACTICE),
    /**
     * does it handle unknown versions correctly?
     */
    HAS_VERSION_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle unknown cipher suites correctly?
     */
    HAS_CIPHERSUITE_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle unknown extensions correctly?
     */
    HAS_EXTENSION_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle long ciphersuite length values correctly?
     */
    HAS_CIPHERSUITE_LENGTH_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle unknown compression algorithms correctly
     */
    HAS_COMPRESSION_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle unknown alpn strings correctly?
     */
    HAS_ALPN_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * 256 - 511 <-- ch should be bigger than this
     */
    HAS_CLIENT_HELLO_LENGTH_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it break on empty last extension
     */
    HAS_EMPTY_LAST_EXTENSION_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle signature and hash algorithms correctly
     */
    HAS_SIG_HASH_ALGORITHM_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * server does not like really big client hello messages
     */
    HAS_BIG_CLIENT_HELLO_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle unknown groups correctly
     */
    HAS_NAMED_GROUP_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * is only the second byte of the ciphersuite evaluated
     */
    HAS_SECOND_CIPHERSUITE_BYTE_BUG(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it ignore the offered ciphersuites
     */
    REFLECTS_OFFERED_CIPHERSUITES(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it ignore the offered ciphersuites
     */
    IGNORES_OFFERED_CIPHERSUITES(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it ignore the offered named groups
     */
    IGNORES_OFFERED_NAMED_GROUPS(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it ignore the sig hash algorithms
     */
    IGNORES_OFFERED_SIG_HASH_ALGOS(AnalyzedPropertyCategory.QUIRKS),
    VULNERABLE_TO_BLEICHENBACHER(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_PADDING_ORACLE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_CBC_PADDING_ORACLE(AnalyzedPropertyCategory.ATTACKS), // ?
    VULNERABLE_TO_INVALID_CURVE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_INVALID_CURVE_EPHEMERAL(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_WITH_REUSE(AnalyzedPropertyCategory.ATTACKS), // ?
    VULNERABLE_TO_POODLE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_TLS_POODLE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_SWEET_32(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_DROWN(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_HEARTBLEED(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_TICKETBLEED(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_EARLY_CCS(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_CRIME(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_BREACH(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_LOGJAM(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_FREAK(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_CVE20162107(AnalyzedPropertyCategory.ATTACKS),
    MISSES_MAC_APPDATA_CHECKS(AnalyzedPropertyCategory.COMPARISSON_FAILURE), // ?
    MISSES_CHECKS_MAC_FINISHED_CHECKS(AnalyzedPropertyCategory.COMPARISSON_FAILURE), // ?
    MISSES_CHECKS_VERIFY_DATA_CHECKS(AnalyzedPropertyCategory.COMPARISSON_FAILURE),// ?
    MISSES_GCM_CHECKS(AnalyzedPropertyCategory.COMPARISSON_FAILURE),
    HAS_CERTIFICATE_ISSUES(AnalyzedPropertyCategory.CERTIFICATE),
    HAS_WEAK_RANDOMNESS(AnalyzedPropertyCategory.FRESHNES), // ?

    REUSES_EC_PUBLICKEY(AnalyzedPropertyCategory.FRESHNES),
    REUSES_DH_PUBLICKEY(AnalyzedPropertyCategory.FRESHNES),
    REUSES_GCM_NONCES(AnalyzedPropertyCategory.FRESHNES),
    REQUIRES_SNI(AnalyzedPropertyCategory.SNI);

    AnalyzedPropertyCategory category;

    AnalyzedProperty(AnalyzedPropertyCategory category) {
        this.category = category;
    }
}
