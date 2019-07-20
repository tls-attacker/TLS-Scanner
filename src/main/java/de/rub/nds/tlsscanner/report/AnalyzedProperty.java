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
        
    SUPPORTS_SSL_2 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_SSL_3 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_0 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_1 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_2 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_14 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_15 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_16 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_17 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_18 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_19 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_20 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_21 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_22 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_23 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_24 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_25 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_26 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_27 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_TLS_1_3_DRAFT_28 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_DTLS_1_0 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_DTLS_1_2 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    SUPPORTS_DTLS_1_3 (AnalyzedPropertyCategory.SUPPORTED_VERSIONS),
    
    SUPPORTS_PFS,
    SUPPORTS_NULL_CIPHERS,
    SUPPORTS_FORTEZZA,
    SUPPORTS_EXPORT,
    SUPPORTS_ANON,
    SUPPORTS_DES,
    SUPPORTS_3DES,
    SUPPORTS_SEED,
    SUPPORTS_IDEA,
    SUPPORTS_RC2,
    SUPPORTS_RC4,
    SUPPORTS_CBC,
    SUPPORTS_AEAD,
    SUPPORTS_POST_QUANTUM,
    SUPPORTS_ONLY_PFS,
    SUPPORTS_AES,
    SUPPORTS_CAMELLIA,
    SUPPORTS_ARIA,
    SUPPORTS_CHACHA,
    SUPPORTS_RSA,
    SUPPORTS_DH,
    SUPPORTS_ECDH,
    SUPPORTS_STATIC_ECDH,
    SUPPORTS_GOST,
    SUPPORTS_SRP,
    SUPPORTS_KERBEROS,
    SUPPORTS_PSK_PLAIN,
    SUPPORTS_PSK_RSA,
    SUPPORTS_PSK_DHE,
    SUPPORTS_PSK_ECDHE,
    SUPPORTS_NEWHOPE,
    SUPPORTS_ECMQV,
    SUPPORTS_STREAM_CIPHERS,
    SUPPORTS_BLOCK_CIPHERS,
       
    SUPPORTS_EXTENDED_MASTER_SECRET,
    SUPPORTS_ENCRYPT_THEN_MAC,
    SUPPORTS_TOKENBINDING,
    
    SUPPORTS_MONTOGMERY_CURVES, // ?
    
    SUPPORTS_SESSION_TICKETS,
    SUPPORTS_SESSION_IDS,
    SUPPORTS_SESSION_TICKETS_ROTATED,
    
    SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
    SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION,
    SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION_EXTENSION,
    SUPPORTS_TLS_FALLBACK_SCSV,
    
    SUPPORTS_TLS_COMPRESSION, // ?
    
    SUPPORTS_COMMON_DH_PRIMES,
    SUPPORTS_PRIME_MODULI,
    SUPPORTS_SAFEPRIME_MODULI,
    
    SUPPORTS_INSECURE_RENEGOTIATION, // ?
    SUPPORTS_RENEGOTIATION, // ?
    
    SUPPORTS_HTTPS,
    SUPPORTS_HSTS,
    SUPPORTS_HSTS_PRELOADING,
    SUPPORTS_HPKP,
    SUPPORTS_HPKP_REPORTING,
    SUPPORTS_HTTP_COMPRESSION, // ?
    
    PREFERS_PFS,
    ENFORCES_PFS, // ?
    ENFOCRES_CS_ORDERING,
    
    /**
     * does it handle unknown versions correctly?
     */
    HAS_VERSION_INTOLERANCE,
    /**
     * does it handle unknown cipher suites correctly?
     */
    HAS_CIPHERSUITE_INTOLERANCE,
    /**
     * does it handle unknown extensions correctly?
     */
    HAS_EXTENSION_INTOLERANCE,
    /**
     * does it handle long ciphersuite length values correctly?
     */    
    HAS_CIPHERSUITE_LENGTH_INTOLERANCE,
    /**
     * does it handle unknown compression algorithms correctly
     */
    HAS_COMPRESSION_INTOLERANCE,
    /**
     * does it handle unknown alpn strings correctly?
     */
    HAS_ALPN_INTOLERANCE,
    /**
     * 256 - 511 <-- ch should be bigger than this
     */
    HAS_CLIENT_HELLO_LENGTH_INTOLERANCE,
    /**
     * does it break on empty last extension
     */
    HAS_EMPTY_LAST_EXTENSION_INTOLERANCE,
    /**
     * does it handle signature and hash algorithms correctly
     */
    HAS_SIG_HASH_ALGORITHM_INTOLERANCE,
    /**
     * server does not like really big client hello messages
     */
    HAS_BIG_CLIENT_HELLO_INTOLERANCE,
    /**
     * does it handle unknown groups correctly
     */   
    HAS_NAMED_GROUP_INTOLERANCE,
    /**
     * is only the second byte of the ciphersuite evaluated
     */
    HAS_SECOND_CIPHERSUITE_BYTE_BUG,
    /**
     * does it ignore the offered ciphersuites
     */
    REFLECTS_OFFERED_CIPHERSUITES,
    /**
     * does it ignore the offered ciphersuites
     */
    IGNORES_OFFERED_CIPHERSUITES,
    /**
     * does it ignore the offered named groups
     */
    IGNORES_OFFERED_NAMED_GROUPS,
    /**
     * does it ignore the sig hash algorithms
     */
    IGNORES_OFFERED_SIG_HASH_ALGOS,
    
    VULNERABLE_TO_BLEICHENBACHER,
    VULNERABLE_TO_PADDING_ORACLE,
    VULNERABLE_TO_CBC_PADDING_ORACLE, // ?
    VULNERABLE_TO_INVALID_CURVE,
    VULNERABLE_TO_INVALID_CURVE_EPHEMERAL,
    VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_WITH_REUSE, // ?
    VULNERABLE_TO_POODLE,
    VULNERABLE_TO_TLS_POODLE,
    VULNERABLE_TO_SWEET_32,
    VULNERABLE_TO_DROWN,
    VULNERABLE_TO_HEARTBLEED,
    VULNERABLE_TO_TICKETBLEED,
    VULNERABLE_TO_EARLY_CCS,
    VULNERABLE_TO_CRIME,
    VULNERABLE_TO_BREACH,
    VULNERABLE_TO_LOGJAM,
    VULNERABLE_TO_FREAK,
    VULNERABLE_TO_CVE20162107,
    
    MISSES_MAC_APPDATA_CHECKS, // ?
    MISSES_CHECKS_MAC_FINISHED_CHECKS, // ?
    MISSES_CHECKS_VERIFY_DATA_CHECKS, // ?
    MISSES_GCM_CHECKS,
            
    HAS_CERTIFICATE_ISSUES,
    HAS_WEAK_RANDOMNESS, // ?
    
    REUSES_EC_PUBLICKEY,
    REUSES_DH_PUBLICKEY,
    REUSES_GCM_NONCES,
    
    REQUIRES_SNI;
    
    AnalyzedPropertyCategory category;
    
    AnalyzedProperty(AnalyzedPropertyCategory category) {
        this.category = category;
    }
}
