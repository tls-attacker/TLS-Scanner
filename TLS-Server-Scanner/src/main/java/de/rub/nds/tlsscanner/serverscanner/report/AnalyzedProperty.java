/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.report;

public enum AnalyzedProperty {

    SUPPORTS_ESNI(AnalyzedPropertyCategory.ESNI),
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
    SUPPORTS_LEGACY_PRF(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_SHA256_PRF(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_SHA384_PRF(AnalyzedPropertyCategory.CIPHER_SUITES),
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
    SUPPORTS_ECDSA(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_RSA_CERT(AnalyzedPropertyCategory.CIPHER_SUITES),
    SUPPORTS_DSS(AnalyzedPropertyCategory.CIPHER_SUITES),
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
    SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2(AnalyzedPropertyCategory.EXTENSIONS),
    SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13(AnalyzedPropertyCategory.EXTENSIONS),
    SUPPORTS_SCTS_PRECERTIFICATE(AnalyzedPropertyCategory.CERTIFICATE_TRANSPARENCY),
    SUPPORTS_SCTS_HANDSHAKE(AnalyzedPropertyCategory.CERTIFICATE_TRANSPARENCY),
    SUPPORTS_SCTS_OCSP(AnalyzedPropertyCategory.CERTIFICATE_TRANSPARENCY),
    SUPPORTS_CHROME_CT_POLICY(AnalyzedPropertyCategory.CERTIFICATE_TRANSPARENCY),
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
    SUPPORTS_TLS13_SECP_COMPRESSION(AnalyzedPropertyCategory.EC),
    SUPPORTS_EXPLICIT_PRIME_CURVE(AnalyzedPropertyCategory.EC),
    SUPPORTS_EXPLICIT_CHAR2_CURVE(AnalyzedPropertyCategory.EC),
    GROUPS_DEPEND_ON_CIPHER(AnalyzedPropertyCategory.EC),
    SUPPORTS_OCSP(AnalyzedPropertyCategory.OCSP),
    PREFERS_PFS(AnalyzedPropertyCategory.BEST_PRACTICES),
    ENFORCES_PFS(AnalyzedPropertyCategory.BEST_PRACTICES),
    ENFOCRES_CS_ORDERING(AnalyzedPropertyCategory.BEST_PRACTICES),
    STRICT_SNI(AnalyzedPropertyCategory.SNI),
    STRICT_ALPN(AnalyzedPropertyCategory.EXTENSIONS),
    /**
     * does it handle unknown versions correctly?
     */
    HAS_VERSION_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle unknown cipher suites correctly?
     */
    HAS_CIPHER_SUITE_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle unknown extensions correctly?
     */
    HAS_EXTENSION_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle long cipher suite length values correctly?
     */
    HAS_CIPHER_SUITE_LENGTH_INTOLERANCE(AnalyzedPropertyCategory.QUIRKS),
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
     * is only the second byte of the cipher suite evaluated
     */
    HAS_SECOND_CIPHER_SUITE_BYTE_BUG(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it ignore the offered cipher suites
     */
    REFLECTS_OFFERED_CIPHER_SUITES(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it ignore the offered cipher suites
     */
    IGNORES_OFFERED_CIPHER_SUITES(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it ignore the offered named groups
     */
    IGNORES_OFFERED_NAMED_GROUPS(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it ignore the sig hash algorithms
     */
    IGNORES_OFFERED_SIG_HASH_ALGOS(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it accept that named groups for ecdsa are missing
     */
    IGNORES_ECDSA_GROUP_DISPARITY(AnalyzedPropertyCategory.QUIRKS),
    /**
     * does it handle a http false start
     */
    SUPPORTS_HTTP_FALSE_START(AnalyzedPropertyCategory.QUIRKS),
    VULNERABLE_TO_SESSION_TICKET_ZERO_KEY(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_DIRECT_RACCOON(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_BLEICHENBACHER(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_PADDING_ORACLE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_INVALID_CURVE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_INVALID_CURVE_EPHEMERAL(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_INVALID_CURVE_TWIST(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_EXPLOITABLE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_POODLE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_TLS_POODLE(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_SWEET_32(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_GENERAL_DROWN(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_EXTRA_CLEAR_DROWN(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_HEARTBLEED(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_TICKETBLEED(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_EARLY_CCS(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_CRIME(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_BREACH(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_LOGJAM(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_FREAK(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_RENEGOTIATION_ATTACK(AnalyzedPropertyCategory.ATTACKS),
    VULNERABLE_TO_RACCOON_ATTACK(AnalyzedPropertyCategory.ATTACKS),
    ALPACA_MITIGATED(AnalyzedPropertyCategory.ATTACKS),
    MISSES_MAC_APPDATA_CHECKS(AnalyzedPropertyCategory.COMPARISON_FAILURE),
    MISSES_MAC_FINISHED_CHECKS(AnalyzedPropertyCategory.COMPARISON_FAILURE),
    MISSES_VERIFY_DATA_CHECKS(AnalyzedPropertyCategory.COMPARISON_FAILURE),
    MISSES_GCM_CHECKS(AnalyzedPropertyCategory.COMPARISON_FAILURE),
    HAS_CERTIFICATE_ISSUES(AnalyzedPropertyCategory.CERTIFICATE),
    MUST_STAPLE(AnalyzedPropertyCategory.OCSP),
    INCLUDES_CERTIFICATE_STATUS_MESSAGE(AnalyzedPropertyCategory.OCSP),
    STAPLED_RESPONSE_EXPIRED(AnalyzedPropertyCategory.OCSP),
    SUPPORTS_NONCE(AnalyzedPropertyCategory.OCSP),
    SUPPORTS_STAPLED_NONCE(AnalyzedPropertyCategory.OCSP),
    SUPPORTS_OCSP_STAPLING(AnalyzedPropertyCategory.OCSP),
    NONCE_MISMATCH(AnalyzedPropertyCategory.OCSP),
    STAPLING_UNRELIABLE(AnalyzedPropertyCategory.OCSP),
    STAPLING_TLS13_MULTIPLE_CERTIFICATES(AnalyzedPropertyCategory.OCSP),
    HAS_WEAK_RANDOMNESS(AnalyzedPropertyCategory.FRESHNESS),
    REUSES_EC_PUBLICKEY(AnalyzedPropertyCategory.FRESHNESS),
    REUSES_DH_PUBLICKEY(AnalyzedPropertyCategory.FRESHNESS),
    REUSES_GCM_NONCES(AnalyzedPropertyCategory.FRESHNESS),
    REQUIRES_SNI(AnalyzedPropertyCategory.SNI),
    HAS_GNU_TLS_MAGIC_BYTES(AnalyzedPropertyCategory.SESSION_TICKET),
    /**
     * CCA Properties
     */
    SUPPORTS_CCA(AnalyzedPropertyCategory.CERTIFICATE),
    REQUIRES_CCA(AnalyzedPropertyCategory.CERTIFICATE),
    VULNERABLE_TO_CCA_BYPASS(AnalyzedPropertyCategory.ATTACKS);

    private AnalyzedPropertyCategory category;

    AnalyzedProperty(AnalyzedPropertyCategory category) {
        this.category = category;
    }

    public AnalyzedPropertyCategory getCategory() {
        return category;
    }
}
