/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report.rating;

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.rating.PropertyResultRatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencer;
import de.rub.nds.scanner.core.report.rating.RatingInfluencers;
import de.rub.nds.scanner.core.report.rating.RatingInfluencersIO;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import jakarta.xml.bind.JAXBException;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
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
                        TlsAnalyzedProperty.ISSUES_TLS13_SESSION_TICKETS_AFTER_HANDSHAKE,
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
                        TlsAnalyzedProperty.DEFAULT_ENCRYPTION_KEY_TICKET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -1000, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.PADDING_ORACLE_TICKET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -900, 500),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.DEFAULT_HMAC_KEY_TICKET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
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
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.UNENCRYPTED_TICKET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -900),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.NO_MAC_CHECK_TICKET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.REUSED_KEYSTREAM_TICKET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -900),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.ALLOW_CIPHERSUITE_CHANGE_TICKET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.ALLOW_VERSION_CHANGE_TICKET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));
        influencers.add(
                new RatingInfluencer(
                        TlsAnalyzedProperty.REUSABLE_TICKET,
                        new PropertyResultRatingInfluencer(TestResults.TRUE, -200),
                        new PropertyResultRatingInfluencer(TestResults.FALSE, 0)));

        // no impact on rating
        List<TlsAnalyzedProperty> neutralProperties =
                new LinkedList<>(
                        Arrays.asList(
                                TlsAnalyzedProperty.SUPPORTED_APPLICATIONS,
                                TlsAnalyzedProperty.SUPPORTED_CIPHERSUITES,
                                TlsAnalyzedProperty.SUPPORTED_EXTENSIONS,
                                TlsAnalyzedProperty.BLEICHENBACHER_TEST_RESULT,
                                TlsAnalyzedProperty.PADDING_ORACLE_TEST_RESULT,
                                TlsAnalyzedProperty.DIRECT_RACCOON_TEST_RESULT,
                                TlsAnalyzedProperty.INVALID_CURVE_TEST_RESULT,
                                TlsAnalyzedProperty.RACCOON_ATTACK_PROBABILITIES,
                                TlsAnalyzedProperty.SUPPORTED_PROTOCOL_VERSIONS,
                                TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS,
                                TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES,
                                TlsAnalyzedProperty.SUPPORTED_NAMED_GROUPS_WITNESSES_TLS13,
                                TlsAnalyzedProperty.SUPPORTED_TLS13_GROUPS,
                                TlsAnalyzedProperty.SUPPORTED_CERT_SIGNATURE_ALGORITHMS,
                                TlsAnalyzedProperty.SUPPORTED_CERT_SIGNATURE_ALGORITHM_OIDS,
                                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_SKE,
                                TlsAnalyzedProperty.SUPPORTED_SIGNATURE_AND_HASH_ALGORITHMS_TLS13,
                                TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_VERSIONS,
                                TlsAnalyzedProperty.SUPPORTED_TOKENBINDING_KEY_PARAMETERS,
                                TlsAnalyzedProperty.SUPPORTED_ALPN_CONSTANTS,
                                TlsAnalyzedProperty.SUPPORTED_COMPRESSION_METHODS,
                                TlsAnalyzedProperty.CERTIFICATE_CHAINS,
                                TlsAnalyzedProperty.STATIC_ECDSA_PK_GROUPS,
                                TlsAnalyzedProperty.EPHEMERAL_ECDSA_PK_GROUPS,
                                TlsAnalyzedProperty.TLS13_ECDSA_PK_GROUPS,
                                TlsAnalyzedProperty.STATIC_ECDSA_SIG_GROUPS,
                                TlsAnalyzedProperty.TLS13_ECDSA_SIG_GROUPS,
                                TlsAnalyzedProperty.OCSP_RESULTS,
                                TlsAnalyzedProperty.EPHEMERAL_ECDSA_SIG_GROUPS,
                                TlsAnalyzedProperty.VERSION_SUITE_PAIRS,
                                TlsAnalyzedProperty.HTTPS_HEADER,
                                TlsAnalyzedProperty.NORMAL_HPKP_PINS,
                                TlsAnalyzedProperty.REPORT_ONLY_HPKP_PINS,
                                TlsAnalyzedProperty.ENTROPY_REPORTS,
                                TlsAnalyzedProperty.MAP_RETRANSMISSION_COUNTERS,
                                TlsAnalyzedProperty.COMMON_DH_VALUES,
                                TlsAnalyzedProperty.CLIENT_SIMULATION_RESULTS,
                                TlsAnalyzedProperty.CCA_TEST_RESULTS,
                                TlsAnalyzedProperty.CLIENT_ADVERTISED_CIPHERSUITES,
                                TlsAnalyzedProperty.CLIENT_ADVERTISED_COMPRESSIONS,
                                TlsAnalyzedProperty.CLIENT_ADVERTISED_NAMED_GROUPS,
                                TlsAnalyzedProperty.CLIENT_ADVERTISED_SIGNATURE_AND_HASH_ALGORITHMS,
                                TlsAnalyzedProperty.CLIENT_ADVERTISED_EXTENSIONS,
                                TlsAnalyzedProperty.CLIENT_ADVERTISED_KEYSHARE_NAMED_GROUPS,
                                TlsAnalyzedProperty.CLIENT_ADVERTISED_POINTFORMATS,
                                TlsAnalyzedProperty.CLIENT_ADVERTISED_ALPNS,
                                TlsAnalyzedProperty
                                        .ISSUES_TLS13_SESSION_TICKETS_WITH_APPLICATION_DATA,
                                TlsAnalyzedProperty.STATISTICS_TICKET,
                                TlsAnalyzedProperty.PROTOCOL_TYPE,
                                TlsAnalyzedProperty.CLOSED_AFTER_FINISHED_DELTA,
                                TlsAnalyzedProperty.CLOSED_AFTER_APP_DATA_DELTA,
                                TlsAnalyzedProperty.KNOWN_PADDING_ORACLE_VULNERABILITY,
                                TlsAnalyzedProperty.MINIMUM_RSA_CERT_KEY_SIZE,
                                TlsAnalyzedProperty.MINIMUM_DSS_CERT_KEY_SIZE,
                                TlsAnalyzedProperty.HSTS_MAX_AGE,
                                TlsAnalyzedProperty.HPKP_MAX_AGE,
                                TlsAnalyzedProperty.GCM_PATTERN,
                                TlsAnalyzedProperty.MAC_CHECK_PATTERN_FIN,
                                TlsAnalyzedProperty.MAC_CHECK_PATTERN_APP_DATA,
                                TlsAnalyzedProperty.VERIFY_CHECK_PATTERN,
                                TlsAnalyzedProperty.HRR_SELECTED_GROUP,
                                TlsAnalyzedProperty.WEAKEST_DH_STRENGTH,
                                TlsAnalyzedProperty.TOTAL_RECEIVED_RETRANSMISSIONS,
                                TlsAnalyzedProperty.COOKIE_LENGTH,
                                TlsAnalyzedProperty.LOWEST_POSSIBLE_DHE_MODULUS_SIZE,
                                TlsAnalyzedProperty.HIGHEST_POSSIBLE_DHE_MODULUS_SIZE,
                                TlsAnalyzedProperty.HANDSHAKE_SUCCESFUL_COUNTER,
                                TlsAnalyzedProperty.HANDSHAKE_FAILED_COUNTER,
                                TlsAnalyzedProperty.CONNECTION_INSECURE_COUNTER,

                                // TODO: decide on rating
                                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_RSA,
                                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DSS,
                                TlsAnalyzedProperty.SERVER_CERT_MIN_KEY_SIZE_DH,
                                TlsAnalyzedProperty.HSTS_INCLUDES_SUBDOMAINS,
                                TlsAnalyzedProperty.HPKP_INCLUDES_SUBDOMAINS,
                                TlsAnalyzedProperty.HSTS_NOT_PARSEABLE,
                                TlsAnalyzedProperty.HPKP_NOT_PARSEABLE,
                                TlsAnalyzedProperty.SUPPORTS_DTLS_1_0_DRAFT,
                                TlsAnalyzedProperty.SUPPORTS_CBC,
                                TlsAnalyzedProperty.SUPPORTS_RSA_SIG,
                                TlsAnalyzedProperty.SUPPORTS_KERBEROS,
                                TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS,
                                TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_EXTENSION,
                                TlsAnalyzedProperty.SUPPORTS_TLS13_PSK,
                                TlsAnalyzedProperty.SUPPORTS_TLS13_PSK_EXCHANGE_MODES,
                                TlsAnalyzedProperty.SUPPORTS_TLS13_0_RTT,
                                TlsAnalyzedProperty
                                        .SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_ID_RESUMPTION,
                                TlsAnalyzedProperty
                                        .SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_SESSION_TICKET_RESUMPTION,
                                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE_IN_RENEGOTIATION,
                                TlsAnalyzedProperty.SUPPORTS_INSECURE_RENEGOTIATION,
                                TlsAnalyzedProperty.SUPPORTS_RENEGOTIATION,
                                TlsAnalyzedProperty.HANDSHAKES_WITH_UNDEFINED_POINT_FORMAT,
                                TlsAnalyzedProperty.SUPPORTS_RECORD_FRAGMENTATION,
                                TlsAnalyzedProperty.HAS_GREASE_CIPHER_SUITE_INTOLERANCE,
                                TlsAnalyzedProperty.HAS_GREASE_NAMED_GROUP_INTOLERANCE,
                                TlsAnalyzedProperty
                                        .HAS_GREASE_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE,
                                TlsAnalyzedProperty.HAS_EC_POINT_FORMAT_INTOLERANCE,
                                TlsAnalyzedProperty.USES_UNIX_TIMESTAMPS_IN_RANDOM,
                                TlsAnalyzedProperty.SENDS_HELLO_RETRY_REQUEST,
                                TlsAnalyzedProperty.ISSUES_COOKIE_IN_HELLO_RETRY,
                                TlsAnalyzedProperty.VULNERABLE_TO_FREAK_DOWNGRADE,
                                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA_SIG,
                                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_RSA,
                                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DSS,
                                TlsAnalyzedProperty.ENFORCES_SERVER_CERT_MIN_KEY_SIZE_DH,
                                TlsAnalyzedProperty.VULNERABLE_TO_CCA_BYPASS,
                                TlsAnalyzedProperty.SUPPORTS_EVEN_MODULUS,
                                TlsAnalyzedProperty.SUPPORTS_MOD3_MODULUS,
                                TlsAnalyzedProperty.SUPPORTS_MODULUS_ONE,
                                TlsAnalyzedProperty.SUPPORTS_GENERATOR_ONE,
                                TlsAnalyzedProperty.SUPPORTS_MODULUS_ZERO,
                                TlsAnalyzedProperty.SUPPORTS_GENERATOR_ZERO,
                                TlsAnalyzedProperty.DTLS_FRAGMENTATION_REQUIRES_EXTENSION,
                                TlsAnalyzedProperty
                                        .DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS_REQUIRES_EXTENSION,
                                TlsAnalyzedProperty.SUPPORTS_RECORD_REORDERING,
                                TlsAnalyzedProperty.SUPPORTS_DTLS_COOKIE_EXCHANGE,
                                TlsAnalyzedProperty.HAS_HVR_RETRANSMISSIONS,
                                TlsAnalyzedProperty.USES_IP_ADDRESS_FOR_COOKIE,
                                TlsAnalyzedProperty.USES_PORT_FOR_COOKIE,
                                TlsAnalyzedProperty.USES_VERSION_FOR_COOKIE,
                                TlsAnalyzedProperty.USES_RANDOM_FOR_COOKIE,
                                TlsAnalyzedProperty.USES_SESSION_ID_FOR_COOKIE,
                                TlsAnalyzedProperty.USES_CIPHERSUITES_FOR_COOKIE,
                                TlsAnalyzedProperty.USES_COMPRESSIONS_FOR_COOKIE,
                                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_FINISHED,
                                TlsAnalyzedProperty.ACCEPTS_UNENCRYPTED_APP_DATA,
                                TlsAnalyzedProperty.HAS_EARLY_FINISHED_BUG,
                                TlsAnalyzedProperty.ACCEPTS_STARTED_WITH_INVALID_MESSAGE_SEQUENCE,
                                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_ONCE,
                                TlsAnalyzedProperty.ACCEPTS_SKIPPED_MESSAGE_SEQUENCES_MULTIPLE,
                                TlsAnalyzedProperty.ACCEPTS_RANDOM_MESSAGE_SEQUENCES,
                                TlsAnalyzedProperty.SENDS_RETRANSMISSIONS,
                                TlsAnalyzedProperty.CHANGES_PORT,
                                TlsAnalyzedProperty.CHANGES_PORT_TO_RANDOM_PORTS,
                                TlsAnalyzedProperty.ACCEPTS_HVR_LEGACY_SERVER_VERSION_MISMATCH,
                                TlsAnalyzedProperty.ACCEPTS_HVR_RECORD_SEQUENCE_NUMBER_MISMATCH,
                                TlsAnalyzedProperty
                                        .ACCEPTS_SERVER_HELLO_RECORD_SEQUENCE_NUMBER_MISMATCH,
                                TlsAnalyzedProperty.HAS_CLIENT_HELLO_MISMATCH,
                                TlsAnalyzedProperty.ACCEPTS_EMPTY_COOKIE,
                                TlsAnalyzedProperty.TLS_1_3_DOWNGRADE_PROTECTION,
                                TlsAnalyzedProperty.FORCED_COMPRESSION,
                                TlsAnalyzedProperty.SENDS_APPLICATION_MESSAGE));

        influencers.addAll(
                neutralProperties.stream().map(RatingInfluencer::new).collect(Collectors.toList()));

        List<String> missingProperties = new ArrayList<>();
        for (TlsAnalyzedProperty tlsAnalyzedProperty : TlsAnalyzedProperty.values()) {
            if (influencers.stream()
                    .noneMatch(
                            influencer ->
                                    influencer.getAnalyzedProperty() == tlsAnalyzedProperty)) {
                missingProperties.add(tlsAnalyzedProperty.name());
            }
        }

        assertTrue(
                missingProperties.isEmpty(),
                "Missing rating influencers for: " + missingProperties);

        new RatingInfluencersIO(TlsAnalyzedProperty.class)
                .write(
                        new File(
                                "src/main/resources/"
                                        + DefaultRatingLoader.INFLUENCERS_RESOURCE_LOCATION),
                        new RatingInfluencers(influencers));
    }
}
