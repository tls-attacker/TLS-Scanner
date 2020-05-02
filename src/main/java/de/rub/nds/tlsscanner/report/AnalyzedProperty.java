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

    SUPPORTS_SSL_2(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_SSL_3(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_0(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_1(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_2(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_14(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_15(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_16(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_17(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_18(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_19(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_20(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_21(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_22(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_23(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_24(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_25(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_26(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_27(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_28(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_DTLS_1_0(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_DTLS_1_2(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_DTLS_1_3(AnalyzedPropertyCategory.VERSIONS),
    SUPPORTS_PFS(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_NULL_CIPHERS(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_FORTEZZA(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_EXPORT(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_ANON(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_DES(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_3DES(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_SEED(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_IDEA(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_RC2(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_RC4(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_CBC(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_AEAD(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_POST_QUANTUM(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_ONLY_PFS(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_AES(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_CAMELLIA(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_ARIA(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_CHACHA(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_RSA(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_DH(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_ECDH(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_STATIC_ECDH(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_GOST(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_SRP(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_KERBEROS(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_PSK_PLAIN(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_PSK_RSA(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_PSK_DHE(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_PSK_ECDHE(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_NEWHOPE(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_ECMQV(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_STREAM_CIPHERS(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_BLOCK_CIPHERS(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_EXTENDED_MASTER_SECRET(AnalyzedPropertyCategory.EXTENSIONS),
    SUPPORTS_ENCRYPT_THEN_MAC(AnalyzedPropertyCategory.EXTENSIONS),
    SUPPORTS_TOKENBINDING(AnalyzedPropertyCategory.EXTENSIONS),
    SUPPORTS_CERTIFICATE_STATUS_REQUEST(AnalyzedPropertyCategory.EXTENSIONS),
    SUPPORTS_MONTGOMERY_CURVES(AnalyzedPropertyCategory.EC),
    SUPPORTS_SESSION_TICKETS(AnalyzedPropertyCategory.SESSION_RESUMPTION),
    SUPPORTS_TLS13_SESSION_TICKETS(AnalyzedPropertyCategory.SESSION_RESUMPTION),
    SUPPORTS_TLS13_PSK_DHE(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_SESSION_IDS(AnalyzedPropertyCategory.SESSION_RESUMPTION),
    SUPPORTS_SESSION_TICKET_ROTATION_HINT(AnalyzedPropertyCategory.SESSION_RESUMPTION),
    SUPPORTS_SECURE_RENEGOTIATION_EXTENSION(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_TLS_FALLBACK_SCSV(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_TLS_COMPRESSION(AnalyzedPropertyCategory.COMPRESSION),
    SUPPORTS_COMMON_DH_PRIMES(AnalyzedPropertyCategory.FFDHE),
    SUPPORTS_ONLY_PRIME_MODULI(AnalyzedPropertyCategory.FFDHE),
    SUPPORTS_ONLY_SAFEPRIME_MODULI(AnalyzedPropertyCategory.FFDHE),
    SUPPORTS_INSECURE_RENEGOTIATION(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_RENEGOTIATION(AnalyzedPropertyCategory.RENEGOTIATION),
    SUPPORTS_HTTPS(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HSTS(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HSTS_PRELOADING(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HPKP(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HPKP_REPORTING(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_HTTP_COMPRESSION(AnalyzedPropertyCategory.HTTPS_HEADERS),
    SUPPORTS_UNCOMPRESSED_POINT(AnalyzedPropertyCategory.EC),
    SUPPORTS_ANSIX962_COMPRESSED_PRIME(AnalyzedPropertyCategory.EC),
    SUPPORTS_ANSIX962_COMPRESSED_CHAR2(AnalyzedPropertyCategory.EC),
    SUPPORTS_SECP_COMPRESSION_TLS13(AnalyzedPropertyCategory.EC),
    PREFERS_PFS(AnalyzedPropertyCategory.BEST_PRACTICES),
    ENFORCES_PFS(AnalyzedPropertyCategory.BEST_PRACTICES),
    ENFOCRES_CS_ORDERING(AnalyzedPropertyCategory.BEST_PRACTICES),
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
    VULNERABLE_TO_INVALID_CURVE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_INVALID_CURVE_EPHEMERAL(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_INVALID_CURVE_TWIST(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_EXPLOITABLE(AnalyzedPropertyCategory.ATTACKS),
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
    VULNERABLE_TO_RENEGOTIATION_ATTACK(AnalyzedPropertyCategory.ATTACKS),
    MISSES_MAC_APPDATA_CHECKS(AnalyzedPropertyCategory.COMPARISON_FAILURE),
    MISSES_MAC_FINISHED_CHECKS(AnalyzedPropertyCategory.COMPARISON_FAILURE),
    MISSES_VERIFY_DATA_CHECKS(AnalyzedPropertyCategory.COMPARISON_FAILURE),
    MISSES_GCM_CHECKS(AnalyzedPropertyCategory.COMPARISON_FAILURE),
    HAS_CERTIFICATE_ISSUES(AnalyzedPropertyCategory.CERTIFICATE),
    MUST_STAPLE(AnalyzedPropertyCategory.OCSP),
    HAS_STAPLED_RESPONSE_DESPITE_SUPPORT(AnalyzedPropertyCategory.OCSP),
    STAPLED_RESPONSE_OUTDATED(AnalyzedPropertyCategory.OCSP),
    SUPPORTS_NONCE(AnalyzedPropertyCategory.OCSP),
    NONCE_MISMATCH(AnalyzedPropertyCategory.OCSP),
    HAS_WEAK_RANDOMNESS(AnalyzedPropertyCategory.FRESHNESS),
    REUSES_EC_PUBLICKEY(AnalyzedPropertyCategory.FRESHNESS),
    REUSES_DH_PUBLICKEY(AnalyzedPropertyCategory.FRESHNESS),
    REUSES_GCM_NONCES(AnalyzedPropertyCategory.FRESHNESS),
    REQUIRES_SNI(AnalyzedPropertyCategory.SNI);

    private AnalyzedPropertyCategory category;

    AnalyzedProperty(AnalyzedPropertyCategory category) {
        this.category = category;
    }

    public AnalyzedPropertyCategory getCategory() {
        return category;
    }
}
