/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.constants.TestResults;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencers;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import jakarta.xml.bind.JAXBException;
import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class DefaultInfluencersIT {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void createDefaultRatingInfluencers() throws IOException, JAXBException {
        LinkedList<RatingInfluencer> influencers = new LinkedList<>();

        // versions
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SSL_2,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -300, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SSL_3,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -200, 1500)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_1_0,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_1_2,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_1_3,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_PFS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -200, 1500)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_FORTEZZA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_EXPORT,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -800, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ANON,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_DES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_3DES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SEED,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_IDEA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_RC2,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_RC4,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_AEAD,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ONLY_PFS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_AES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CAMELLIA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ARIA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CHACHA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_RSA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_DHE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ECDHE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_STATIC_DH,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_GOST,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SRP,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_PSK_RSA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_PSK_DHE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_NEWHOPE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ECMQV,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TOKENBINDING,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_MONTGOMERY_CURVES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_ROTATION_HINT,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION,
                        new PropertyResultRatingInfluencer(
                                TestResults.TRUE,
                                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V1,
                                TestResults.TRUE),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION,
                        new PropertyResultRatingInfluencer(
                                TestResults.TRUE,
                                TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V2,
                                TestResults.TRUE),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION,
                        new PropertyResultRatingInfluencer(
                                TestResults.TRUE,
                                TlsAnalyzedProperty
                                        .VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V1,
                                TestResults.TRUE),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION,
                        new PropertyResultRatingInfluencer(
                                TestResults.TRUE,
                                TlsAnalyzedProperty
                                        .VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V2,
                                TestResults.TRUE),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION,
                        new PropertyResultRatingInfluencer(
                                TestResults.TRUE,
                                TlsAnalyzedProperty.VULNERABLE_TO_CRIME,
                                TestResults.TRUE),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 100)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -200, 1500)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -100)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_HTTPS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_HSTS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_HPKP,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_HTTP_COMPRESSION,
                        new PropertyResultRatingInfluencer(
                                TestResults.TRUE,
                                TlsAnalyzedProperty.VULNERABLE_TO_BREACH,
                                TestResults.TRUE),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.PREFERS_PFS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.ENFORCES_PFS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.ENFORCES_CS_ORDERING,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.ENFORCES_SIGNATURE_HASH_ALGORITHM_ORDERING,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -800, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -800, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -1200, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_TICKETBLEED,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -800, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -1200, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_EXPLOITABLE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -800, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_POODLE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -300, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -300, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_CRIME,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_BREACH,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_LOGJAM,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_FREAK,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V1,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V2,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V1,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V2,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.MISSES_MAC_APPDATA_CHECKS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.MISSES_MAC_FINISHED_CHECKS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.MISSES_VERIFY_DATA_CHECKS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.MISSES_GCM_CHECKS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.REUSES_GCM_NONCES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_CERTIFICATE_ISSUES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_WEAK_RANDOMNESS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -500, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.REUSES_EC_PUBLICKEY,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.REUSES_DH_PUBLICKEY,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.REQUIRES_SNI,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_14,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_15,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_16,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_17,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_18,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_19,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_20,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_21,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_22,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_23,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_24,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_25,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_26,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_27,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT_28,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200, 1000),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_LEGACY_PRF,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SHA256_PRF,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SHA384_PRF,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ECDSA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_RSA_CERT,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_DSS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_EXPLICIT_PRIME_CURVE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_EXPLICIT_CHAR2_CURVE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS13_SESSION_TICKETS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_OCSP,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.MUST_STAPLE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.INCLUDES_CERTIFICATE_STATUS_MESSAGE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.STAPLED_RESPONSE_EXPIRED,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_NONCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.NONCE_MISMATCH,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.STAPLING_UNRELIABLE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_HTTP_FALSE_START,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_SESSION_TICKET_ZERO_KEY,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -1000, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_DIRECT_RACCOON,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -800, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_RACCOON_ATTACK,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_STAPLED_NONCE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 25),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_OCSP_STAPLING,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.STAPLING_TLS13_MULTIPLE_CERTIFICATES,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.IGNORES_ECDSA_GROUP_DISPARITY,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_EXTRA_CLEAR_DROWN,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -800, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_TWIST,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -1200, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CCA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.REQUIRES_CCA,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_DHE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_V2,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CERTIFICATE_STATUS_REQUEST_TLS13,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SCTS_PRECERTIFICATE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SCTS_HANDSHAKE,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_SCTS_OCSP,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_CHROME_CT_POLICY,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_UNCOMPRESSED_POINT,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_PRIME,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ANSIX962_COMPRESSED_CHAR2,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_TLS13_SECP_COMPRESSION,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -50),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.GROUPS_DEPEND_ON_CIPHER,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_ESNI,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.STRICT_ALPN,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.STRICT_SNI,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 100),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -50)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.ALPACA_MITIGATED,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -200)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.SUPPORTS_REORDERING,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.HAS_COOKIE_CHECKS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, 0),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, -100)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        RatingInfluencersIO.write(
                new File("src/main/resources/" + DefaultRatingLoader.INFLUENCERS_RESOURCE_LOCATION),
                new RatingInfluencers(influencers));
    }
}
