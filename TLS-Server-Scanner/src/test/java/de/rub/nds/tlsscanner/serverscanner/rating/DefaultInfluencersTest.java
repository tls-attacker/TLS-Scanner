/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.rating;

import de.rub.nds.tlsscanner.serverscanner.report.AnalyzedProperty;
import java.io.File;
import java.util.LinkedList;
import org.junit.Test;

public class DefaultInfluencersTest {

    @Test
    public void createDefaultRatingInfluencers() {
        LinkedList<RatingInfluencer> influencers = new LinkedList<>();

        // versions
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_SSL_2,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -300, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_SSL_3,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_1_0,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_1_1,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_1_2,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -200, 1500)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_1_3,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_DTLS_1_0,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -300),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_DTLS_1_2,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -300),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_DTLS_1_3,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -300),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_PFS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -200, 1500)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_NULL_CIPHERS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_FORTEZZA,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_EXPORT,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -800, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_ANON,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_DES,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_3DES,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_SEED,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_IDEA,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_RC2,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_RC4,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_CBC,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_AEAD,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -100)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_POST_QUANTUM,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_ONLY_PFS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_AES,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_CAMELLIA,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(
            new RatingInfluencer(AnalyzedProperty.SUPPORTS_ARIA, new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
                new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_CHACHA,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_RSA,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 100)));
        influencers.add(
            new RatingInfluencer(AnalyzedProperty.SUPPORTS_DH, new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
                new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_ECDH,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_STATIC_ECDH,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_GOST,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(
            new RatingInfluencer(AnalyzedProperty.SUPPORTS_SRP, new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
                new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_KERBEROS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_PSK_PLAIN,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_PSK_RSA,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_PSK_DHE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_PSK_ECDHE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_NEWHOPE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_ECMQV,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_STREAM_CIPHERS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_TOKENBINDING,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_MONTGOMERY_CURVES,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_SESSION_TICKETS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_SESSION_IDS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_SESSION_TICKET_ROTATION_HINT,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION,
            new PropertyResultRatingInfluencer(TestResult.TRUE,
                AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION, TestResult.TRUE),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION,
            new PropertyResultRatingInfluencer(TestResult.TRUE,
                AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE, TestResult.TRUE),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_INSECURE_RENEGOTIATION,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_RENEGOTIATION,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_TLS_COMPRESSION,
            new PropertyResultRatingInfluencer(TestResult.TRUE, AnalyzedProperty.VULNERABLE_TO_CRIME, TestResult.TRUE),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 100)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -200, 1500)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -100)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_HTTPS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_HSTS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -100)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_HSTS_PRELOADING,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_HPKP,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_HPKP_REPORTING,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.SUPPORTS_HTTP_COMPRESSION,
            new PropertyResultRatingInfluencer(TestResult.TRUE, AnalyzedProperty.VULNERABLE_TO_BREACH, TestResult.TRUE),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));

        influencers.add(
            new RatingInfluencer(AnalyzedProperty.PREFERS_PFS, new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
                new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.ENFORCES_PFS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.ENFORCES_CS_ORDERING,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 50),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_VERSION_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_EXTENSION_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_COMPRESSION_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_ALPN_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -800, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -800, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_HEARTBLEED,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -1200, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_TICKETBLEED,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -800, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -1200, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_EXPLOITABLE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -800, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_POODLE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_TLS_POODLE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -800, 500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_SWEET_32,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -300, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -300, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_CRIME,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_BREACH,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -100),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_LOGJAM,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_FREAK,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.MISSES_MAC_APPDATA_CHECKS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.MISSES_MAC_FINISHED_CHECKS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.MISSES_VERIFY_DATA_CHECKS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.MISSES_GCM_CHECKS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.REUSES_GCM_NONCES,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_CERTIFICATE_ISSUES,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.HAS_WEAK_RANDOMNESS,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -500, 1000),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));

        influencers.add(new RatingInfluencer(AnalyzedProperty.REUSES_EC_PUBLICKEY,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200, 1500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.REUSES_DH_PUBLICKEY,
            new PropertyResultRatingInfluencer(TestResult.TRUE, -200, 1500),
            new PropertyResultRatingInfluencer(TestResult.FALSE, 50)));
        influencers.add(
            new RatingInfluencer(AnalyzedProperty.REQUIRES_SNI, new PropertyResultRatingInfluencer(TestResult.TRUE, 0),
                new PropertyResultRatingInfluencer(TestResult.FALSE, 0)));
        influencers.add(
            new RatingInfluencer(AnalyzedProperty.STRICT_ALPN, new PropertyResultRatingInfluencer(TestResult.TRUE, 200),
                new PropertyResultRatingInfluencer(TestResult.FALSE, -100)));
        influencers.add(
            new RatingInfluencer(AnalyzedProperty.STRICT_SNI, new PropertyResultRatingInfluencer(TestResult.TRUE, 100),
                new PropertyResultRatingInfluencer(TestResult.FALSE, -50)));
        influencers.add(new RatingInfluencer(AnalyzedProperty.ALPACA_MITIGATED,
            new PropertyResultRatingInfluencer(TestResult.TRUE, 200),
            new PropertyResultRatingInfluencer(TestResult.FALSE, -200)));
        RatingIO.writeRatingInfluencers(new RatingInfluencers(influencers),
            new File("src/main/resources/" + RatingInfluencers.DEFAULT_RATING_FILE));
    }
}
