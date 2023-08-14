/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report.rating;

import de.rub.nds.scanner.core.probe.result.TestResults;
import de.rub.nds.scanner.core.report.rating.PropertyResultRecommendation;
import de.rub.nds.scanner.core.report.rating.Recommendation;
import de.rub.nds.scanner.core.report.rating.Recommendations;
import de.rub.nds.scanner.core.report.rating.RecommendationsIO;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsAnalyzedProperty;
import jakarta.xml.bind.JAXBException;
import java.io.File;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class DefaultRecommendationsIT {

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void createDefaultRatingInfluencers() throws IOException, JAXBException {
        List<Recommendation> recommendations = new LinkedList<>();

        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_SSL_2,
                        "SSL 2.0 support",
                        "Evaluates whether the SSL 2.0 protocol is supported",
                        new PropertyResultRecommendation(
                                TestResults.TRUE, "SSL 2.0 is enabled", "Disable SSL 2.0", ""),
                        "https://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html",
                        "https://drownattack.com"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_SSL_3,
                        "SSL 3.0 support",
                        "Evaluates whether the SSL 3.0 protocol is supported",
                        new PropertyResultRecommendation(
                                TestResults.TRUE, "SSL 3.0 is enabled", "Disable SSL 3.0"),
                        "https://tools.ietf.org/html/rfc6101",
                        "https://www.openssl.org/~bodo/ssl-poodle.pdf"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_0,
                        "TLS 1.0 support",
                        "Evaluates whether the TLS 1.0 protocol is supported",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "TLS 1.0 is enabled",
                                "Consider disabling TLS 1.0",
                                ""),
                        "https://www.ietf.org/rfc/rfc2246"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_1,
                        "TLS 1.1 support",
                        "Evaluates whether the TLS 1.1 protocol is supported",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "TLS 1.1 is enabled",
                                "Consider disabling TLS 1.1",
                                ""),
                        "https://www.ietf.org/rfc/rfc4346"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_2,
                        "TLS 1.2 support",
                        "Evaluates whether the TLS 1.2 protocol is supported",
                        new PropertyResultRecommendation(
                                TestResults.FALSE, "TLS 1.2 is disabled", "Enable TLS 1.2"),
                        "https://www.ietf.org/rfc/rfc5246.txt"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3,
                        "TLS 1.3 support",
                        "Evaluates whether the TLS 1.3 protocol is supported",
                        new PropertyResultRecommendation(
                                TestResults.FALSE, "TLS 1.3 is disabled", "Enable TLS 1.3"),
                        "https://tools.ietf.org/html/rfc8446"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT,
                        "TLS 1.3 draft version support",
                        "Evaluates whether a TLS 1.3 version draft is supported",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "TLS 1.3 draft version is enabled",
                                "Update your server and enable the TLS 1.3 final version"),
                        "https://tools.ietf.org/html/rfc8446"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_1_0,
                        "DTLS 1.0 support",
                        "Evaluates whether the DTLS 1.0 protocol is supported",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "DTLS 1.0 is enabled",
                                "Consider disabling DTLS 1.0"),
                        "https://tools.ietf.org/html/rfc4347"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_1_2,
                        "DTLS 1.2 support",
                        "Evaluates whether the DTLS 1.2 protocol is supported",
                        new PropertyResultRecommendation(
                                TestResults.FALSE, "DTLS 1.2 is disabled", "Enable DTLS 1.2"),
                        "https://tools.ietf.org/html/rfc6347"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_1_3,
                        "DTLS 1.3 support",
                        "Evaluates whether the DTLS 1.3 protocol is supported",
                        new PropertyResultRecommendation(
                                TestResults.FALSE, "DTLS 1.3 is disabled", "Enable DTLS 1.3"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_NULL_CIPHERS,
                        "Null cipher support",
                        "Evaluates whether the server supports null ciphers",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "Null ciphers are supported",
                                "Disable insecure null ciphers"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_FORTEZZA,
                        "Fortezza support",
                        "Evaluates whether the server supports Fortezza ciphers",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "Fortezza ciphers are supported",
                                "Disable Fortezza cipher suites",
                                "Fortezza cipher suites were developed by NSA in the 90s. You should better get rid of Fortezza algorithms."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_EXPORT,
                        "Export cipher support",
                        "Evaluates whether the server supports export ciphers",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "Export ciphers are enabled",
                                "Disable export ciphers",
                                ""),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_ANON,
                        "Anonymous cipher support",
                        "Evaluates whether the server supports anonymous ciphers",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "Anonymous ciphers are enabled",
                                "Disable anonymous ciphers"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_DES,
                        "DES support",
                        "Evaluates whether the server supports DES ciphers",
                        new PropertyResultRecommendation(
                                TestResults.TRUE, "DES ciphers are enabled", "Disable DES ciphers"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_3DES,
                        "3DES (Triple DES) support",
                        "Evaluates whether the server supports 3DES (Triple DES) ciphers",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "3DES ciphers are enabled",
                                "Disable 3DES ciphers"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_SEED,
                        "SEED cipher support",
                        "Evaluates whether the server supports SEED ciphers",
                        "SEED is a 128 bit block cipher developed by the KISA (Korea Information Security Agency) in 1998",
                        "https://tools.ietf.org/html/rfc4162"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_IDEA,
                        "IDEA cipher support",
                        "Evaluates whether the server supports IDEA ciphers",
                        "IDEA (International Data Encryption Algorithm) is a block cipher. It uses a 128 bit key and operates on 64 bit blocks.",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "IDEA ciphers are enabled",
                                "Disable IDEA ciphers"),
                        "https://tools.ietf.org/html/rfc5469"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_RC2,
                        "RC2 cipher support",
                        "Evaluates whether the server supports RC2 ciphers",
                        "RC2 is a 64 bit block cipher designed by Ron Rivest in 1987",
                        new PropertyResultRecommendation(
                                TestResults.TRUE, "RC2 ciphers are enabled", "Disable RC2 ciphers"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_RC4,
                        "RC4 cipher support",
                        "Evaluates whether the server supports RC4 ciphers",
                        "RC4 is a stream cipher designed by Ron Rivest in 1987",
                        new PropertyResultRecommendation(
                                TestResults.TRUE, "RC4 ciphers are enabled", "Disable RC4 ciphers"),
                        "https://tools.ietf.org/html/rfc7465",
                        "https://www.rc4nomore.com/"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_AEAD,
                        "AEAD cipher suites support",
                        "Evaluates whether the server supports AEAD (Authenticated Encryption with Associated Data) cipher suites, e.g., AES-GCM",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "AEAD cipher suites are disabled",
                                "Enable AEAD cipher suites, e.g., AES-GCM"),
                        ""));

        // PFS
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_PFS,
                        "Perfect Forward Secrecy (PFS) support",
                        "Evaluates whether the server supports Perfect Forward Secrecy (PFS)",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "PFS is not supported",
                                "Enable perfect forward secure cipher suites, e.g., TLS-DHE or TLS-ECDHE"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_ONLY_PFS,
                        "Support for only PFS cipher suites",
                        "Evaluates whether the server exclusively supports Perfect Forward Secrecy (PFS)",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Not all cipher suites are perfect forward secure",
                                "Consider disabling cipher suites which are not perfect forward secure. Enable only perfect forward secure cipher suites, e.g., TLS-DHE or TLS-ECDHE"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.PREFERS_PFS,
                        "Perfect Forward Secrecy (PFS) preference",
                        "Evaluates whether the server prefers Perfect Forward Secrecy (PFS) cipher suites",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "PFS cipher suites are not preferred",
                                "Enable cipher suite ordering and prefer PFS cipher suites"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.ENFORCES_PFS,
                        "Perfect Forward Secrecy (PFS) enforcing",
                        "Evaluates whether the server enforces Perfect Forward Secrecy (PFS) cipher suites",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "PFS cipher suites are not enforced",
                                "Enable cipher suite ordering and enforce PFS cipher suites"),
                        ""));

        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_AES,
                        "AES cipher support",
                        "Evaluates whether the server supports AES cipher",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "AES cipher suites are disabled",
                                "Enable AES cipher suites"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_CAMELLIA,
                        "Camellia cipher support",
                        "Evaluates whether the server supports Camellia cipher",
                        "Camellia is a 128 bit block cipher designed by Mitsubishi and NTT in 2000",
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_ARIA,
                        "ARIA cipher support",
                        "Evaluates whether the server supports ARIA cipher",
                        "ARIA is a 128 bit block cipher designed in 2003",
                        "https://tools.ietf.org/html/rfc5794"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_CHACHA,
                        "ChaCha cipher support",
                        "Evaluates whether the server supports ChaCha cipher",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "ChaCha cipher is disabled",
                                "Enable ChaCha cipher"),
                        "https://tools.ietf.org/html/rfc7905"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_RSA,
                        "RSA key exchange support",
                        "Evaluates whether the server supports RSA key exchange",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "RSA key exchange is enabled",
                                "Disable RSA key exchange"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_STATIC_DH,
                        "Diffie-Hellman (DH) key exchange support",
                        "Evaluates whether the server supports Diffie-Hellman (DH) key exchange",
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH,
                        "Elliptic Curve Diffie-Hellman (ECDH) key exchange support",
                        "Evaluates whether the server supports Elliptic Curve Diffie-Hellman (ECDH) key exchange",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Elliptic Curve Diffie-Hellman (ECDH) key exchange is disabled",
                                "Enable Elliptic Curve Diffie-Hellman (ECDH)"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_STATIC_ECDH,
                        "Static Elliptic Curve Diffie-Hellman (ECDH) key exchange support",
                        "Evaluates whether the server supports static Elliptic Curve Diffie-Hellman (ECDH) key exchange",
                        "",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "Static Elliptic Curve Diffie-Hellman (ECDH) key exchange is enabled",
                                "Disable static Elliptic Curve Diffie-Hellman (ECDH)"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_GOST,
                        "GOST cipher support",
                        "Evaluates whether the server supports GOST cipher",
                        "GOST is a block cipher designed in the USSR in the nineties. It has a block size of 64 bits. ",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "GOST ciphers are enabled",
                                "Disable GOST ciphers"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_SRP,
                        "Secure Remote Password (SRP) support",
                        "Evaluates whether the server supports Secure Remote Password (SRP) cipher suites",
                        "https://tools.ietf.org/html/rfc5054"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_KERBEROS,
                        "Kerberos cipher suites support",
                        "Evaluates whether the server supports Kerberos cipher suites",
                        "https://tools.ietf.org/html/rfc2712"));

        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_PSK_PLAIN,
                        "Supports plain PSK",
                        "For now we do not consider in our scoring",
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_PSK_RSA,
                        "Supports RSA PSK",
                        "For now we do not consider in our scoring",
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_PSK_DHE,
                        "Supports DHE PSK",
                        "For now we do not consider in our scoring",
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_PSK_ECDHE,
                        "Supports ECDHE PSK",
                        "For now we do not consider in our scoring",
                        ""));

        // post quantum
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_POST_QUANTUM,
                        "Post quantum algorithms support",
                        "Evaluates whether the server supports post quantum algorithms",
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_NEWHOPE,
                        "Post quantum new hope algorithm support",
                        "Evaluates whether the server supports the new hope post quantum algorithm",
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_ECMQV,
                        "Post quantum ECMQV algorithm support",
                        "Evaluates whether the server supports the ECMQV post quantum algorithm",
                        ""));

        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_STREAM_CIPHERS,
                        "Stream cipher support",
                        "Evaluates whether the server supports stream ciphers",
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_BLOCK_CIPHERS,
                        "Block cipher support",
                        "Evaluates whether the server supports block ciphers",
                        ""));

        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET,
                        "Extended master secret support",
                        "Evaluates whether the server supports extended master secret extension",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Extended master secret extension is not supported",
                                "Enable support for the extended master secret"),
                        "https://tools.ietf.org/html/rfc7627"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC,
                        "Encrypt-then-MAC extension support",
                        "Evaluates whether the server supports Encrypt-then-MAC extension",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Encrypt-then-MAC extension is not supported",
                                "Enable support for the Encrypt-then-MAC"),
                        "https://tools.ietf.org/html/rfc7366"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_TOKENBINDING,
                        "Token binding support",
                        "Evaluates whether the server supports token binding",
                        ""));

        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_MONTGOMERY_CURVES,
                        "Montgomery curve support",
                        "",
                        ""));

        // session resumption
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_RESUMPTION,
                        "Support for session resumption with session tickets",
                        "Evaluates whether the server supports session resumption with session tickets",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Session tickets are disabled",
                                "Enable session resumption with session tickets"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_SESSION_ID_RESUMPTION,
                        "Support for session resumption with session IDs",
                        "Evaluates whether the server supports session resumption with session IDs",
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_SESSION_TICKET_ROTATION_HINT,
                        "Support for rotated session tickets",
                        "Evaluates whether the server supports session resumption with session tickets whose keys are being rotated",
                        "Session tickets are created with symmetric keys. The lifetime of the symmetric keys used for session tickets should be restricted to reduce the attack surface. The ticket lifetime is typically indicated in the ticket lifetime hint.",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Session resumption with rotating session tickets is disabled",
                                "Frequently changing session ticket keys improves the security, enable rotated session tickets."),
                        ""));

        // Renegotiation
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION,
                        "Support for secure renegotiation extension",
                        "Evaluates whether the server supports secure renegotiation extension.",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Secure renegotiation extension is disabled",
                                "Consider to enable secure renegotiation extension."),
                        "https://tools.ietf.org/html/rfc5746"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_CIPHERSUITE,
                        "Support for client-side secure renegotiation",
                        "Evaluates whether the server supports client-side secure renegotiation.",
                        "Secure renegotiation can be started by the client as well as by the server. In its configuration the server can restrict the support for the server-side secure renegotiation. In that case, only the server can start the renegotiation process.",
                        "https://tools.ietf.org/html/rfc5746"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION_EXTENSION,
                        "Support for client-side secure renegotiation",
                        "Evaluates whether the server supports client-side secure renegotiation.",
                        "Secure renegotiation can be started by the client as well as by the server. In its configuration the server can restrict the support for the server-side secure renegotiation. In that case, only the server can start the renegotiation process.",
                        "https://tools.ietf.org/html/rfc5746"));

        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV,
                        "TLS Fallback Signaling Cipher Suite Value (SCSV) support",
                        "Evaluates whether the server supports TLS Fallback Signaling Cipher Suite Value (SCSV)",
                        "In order to establish the highest possible TLS version, TLS clients attempt to perform several TLS "
                                + "handshake starting with the one with the highest version. If a TLS handshake with a particular"
                                + " version does not work, the TLS client attempts to execute the handshake with a lower version. This of course allows an attacker to downgrade the TLS connection. TLS Fallback Signaling Cipher Suite Value (SCSV) was introduced to prevent downgrade attacks. For example, if a TLS client attempts to establish a TLS 1.1 connection after an unsuccessful TLS 1.2 handshake attempt, it includes a TLS SCSV cipher suite into the ClientHello message. The server accepts this handshake if and only if its highest version is TLS 1.1.",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "TLS SCSV is disabled",
                                " Enable TLS Fallback Signaling Cipher Suite Value (SCSV)"),
                        "https://tools.ietf.org/html/rfc7507"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_TLS_COMPRESSION,
                        "TLS compression support",
                        "Evaluates whether the server supports TLS compression",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "TLS compression is supported",
                                "Disable TLS compression"),
                        ""));

        // safe prime -> custom prime (-50) -> common prime (-100) -> non prime
        // (-500)
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_ONLY_PRIME_MODULI,
                        "Moduli provided in FFDHE ServerKeyExchange messages are prime",
                        "Evaluates whether the group moduli provided in FFDHE (finite field Diffie-Hellman ephemeral) ServerKeyExchange messages are prime",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "DH group moduli are not prime",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        "https://eprint.iacr.org/2016/995.pdf"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES,
                        "Moduli provided in FFDHE ServerKeyExchange messages are from common groups",
                        "Evaluates whether the group moduli provided in FFDHE (finite field Diffie-Hellman ephemeral) ServerKeyExchange messages are from common groups defined by standardization bodies or RFCs",
                        "https://github.com/cryptosense/diffie-hellman-groups",
                        "https://eprint.iacr.org/2016/995.pdf"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_ONLY_SAFEPRIME_MODULI,
                        "Moduli provided in FFDHE ServerKeyExchange messages are safe primes",
                        "Evaluates whether the group moduli provided in FFDHE (finite field Diffie-Hellman ephemeral) ServerKeyExchange messages are safe primes",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "DH group moduli are not safe primes",
                                "There is a vulnerability in your implementation. Update your software or contact the developers."),
                        "https://eprint.iacr.org/2016/995.pdf"));

        // HTTP
        recommendations.add(
                new Recommendation(TlsAnalyzedProperty.SUPPORTS_HTTPS, "HTTPS support", "", ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_HSTS,
                        "Support for HTTP Strict Transport Security (HSTS)",
                        "Evaluates whether the server supports HTTP Strict Transport Security (HSTS)",
                        new PropertyResultRecommendation(
                                TestResults.FALSE, "HSTS is disabled", "Enable HSTS"),
                        "https://tools.ietf.org/html/rfc6797"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_HSTS_PRELOADING,
                        "Support for HTTP Strict Transport Security (HSTS) preloading",
                        "",
                        new PropertyResultRecommendation(
                                TestResults.FALSE, "HSTS is disabled", "Enable HSTS"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_HPKP,
                        "HTTP Public Key Pinning (HPKP) support",
                        "Evaluates whether the server supports Public Key Pinning Extension for HTTP",
                        "https://tools.ietf.org/html/rfc7469"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_HPKP_REPORTING,
                        "HTTP Public Key Pinning (HPKP) report-only mode support",
                        "Evaluates whether the server supports Public Key Pinning Extension for HTTP in a report-only mode",
                        "https://tools.ietf.org/html/rfc7469"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_HTTP_COMPRESSION,
                        "HTTP compression support",
                        "Evaluates whether the server supports HTTP compression",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "HTTP compression is enabled",
                                "Disable HTTP compression"),
                        ""));

        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.ENFORCES_CS_ORDERING,
                        "Cipher suite ordering support",
                        "Evaluates whether the server supports cipher suite ordering",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Cipher suite ordering is disabled",
                                "Enable cipher suite ordering"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.ENFORCES_NAMED_GROUP_ORDERING,
                        "Named group order",
                        "Evaluates whether the server enforces the client's named group ordering",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Server does not enforce client's group order",
                                "Enforce client's group order")));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.ENFORCES_SIGNATURE_HASH_ALGORITHM_ORDERING,
                        "Signature has algorithm ordering enforced",
                        "Evaluates whether the server enforces signature hash algorithm ordering",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "Signature hash ordering is not enforced",
                                "Enforce signature hash algorithm ordering"),
                        ""));

        // intolerances
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_VERSION_INTOLERANCE,
                        "TLS version intolerance",
                        "Evaluates whether the server is TLS version intolerant",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is TLS version intolerant",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_CIPHER_SUITE_INTOLERANCE,
                        "TLS cipher suite intolerance",
                        "Evaluates whether the server is cipher suite intolerant",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is cipher suite intolerant",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_EXTENSION_INTOLERANCE,
                        "TLS extension intolerance",
                        "Evaluates whether the server is TLS extension intolerant",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is TLS extension intolerant",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_CIPHER_SUITE_LENGTH_INTOLERANCE,
                        "TLS cipher suite length intolerance",
                        "Evaluates whether the server has TLS cipher suite length intolerance",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server has TLS cipher suite length intolerance",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_COMPRESSION_INTOLERANCE,
                        "TLS compression intolerance",
                        "Evaluates whether the server is TLS compression intolerant",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is TLS compression intolerant",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_ALPN_INTOLERANCE,
                        "ALPN intolerance",
                        "Evaluates whether the server has Application-Layer Protocol Negotiation (ALPN) intolerance",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is ALPN intolerant",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE,
                        "ClientHello length intolerance",
                        "Evaluates whether the server has ClientHello length intolerance",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server has ClientHello length intolerance",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE,
                        "ClientHello last extension intolerance",
                        "Evaluates whether the server has ClientHello last extension intolerance",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server has ClientHello last extension intolerance",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE,
                        "Signature and hash algorithm intolerance",
                        "Evaluates whether the server has TLS signature and hash algorithm intolerance",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server has TLS signature and hash algorithm intolerance",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE,
                        "Big ClientHello intolerance",
                        "Evaluates whether the server has big ClientHello intolerance",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server has big ClientHello intolerance",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE,
                        "Elliptic curve named group intolerance",
                        "Evaluates whether the server has elliptic curve named group intolerance",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server has elliptic curve named group intolerance",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_SECOND_CIPHER_SUITE_BYTE_BUG,
                        "Second cipher suite bug",
                        "Evaluates whether the server always evaluates only the second cipher suite byte",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server always evaluates only the second cipher suite byte",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.REFLECTS_OFFERED_CIPHER_SUITES,
                        "Cipher suite reflection",
                        "Evaluates whether the server reflects offered cipher suites",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server reflects offered cipher suites",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.IGNORES_OFFERED_CIPHER_SUITES,
                        "Ignoring offered cipher suites",
                        "Evaluates whether the server ignores offered cipher suites",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server ignores offered cipher suites",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS,
                        "Ignoring offered named groups",
                        "Evaluates whether the server ignores offered named groups",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server ignores offered named groups",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS,
                        "Ignoring offered signature and hash algorithms",
                        "Evaluates whether the server ignores offered signature and hash algorithms",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server ignores offered signature and hash algorithms",
                                "There is a bug in your implementation. Update your software or contact the developers."),
                        ""));

        // Attacks
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER,
                        "Vulnerable to a Bleichenbacher attack",
                        "Evaluates whether the server is vulnerable to a Bleichenbacher attack",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to a Bleichenbacher attack",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        "https://robotattack.org/"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE,
                        "Vulnerable to a CBC padding oracle attack vulnerability",
                        "Evaluates whether the server is vulnerable to a CBC padding oracle attack",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to a CBC padding oracle attack",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE,
                        "Vulnerable to an invalid curve attack",
                        "Evaluates whether the server is vulnerable to an invalid curve attack",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to an invalid curve attack",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL,
                        "Vulnerable to an invalid curve attack on ephemeral cipher suites",
                        "Evaluates whether the server is vulnerable to an invalid curve attack on ephemeral cipher suites",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to an invalid curve attack on ephemeral cipher suites",
                                "There is a vulnerability in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_EXPLOITABLE,
                        "Vulnerable to an invalid curve attack on ephemeral cipher suites with key reuse",
                        "Evaluates whether the server is vulnerable to an invalid curve attack on ephemeral cipher suites with key reuse",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to an invalid curve attack on ephemeral cipher suites with key reuse",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_POODLE,
                        "Vulnerable to POODLE",
                        "Evaluates whether the server is vulnerable to POODLE (Padding Oracle On Downgraded Legacy Encryption)",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to POODLE",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        "https://www.openssl.org/~bodo/ssl-poodle.pdf"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_SWEET_32,
                        "Vulnerable to Sweet32",
                        "Evaluates whether the server is vulnerable to Sweet32",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to Sweet32",
                                "Disable 64 bit block ciphers like 3DES."),
                        "https://sweet32.info"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_GENERAL_DROWN,
                        "Vulnerable to DROWN",
                        "Evaluates whether the server is vulnerable to DROWN (Decrypting RSA with Obsolete and Weakened "
                                + "encryption)",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to DROWN",
                                "Disable SSL 2.0"),
                        "https://drownattack.com"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_HEARTBLEED,
                        "Vulnerable to Heartbleed",
                        "Evaluates whether the server is vulnerable to Heartbleed",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to Heartbleed",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        "http://heartbleed.com"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_TICKETBLEED,
                        "Vulnerable to Ticketbleed",
                        "Evaluates whether the server is vulnerable to Ticketbleed",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to Ticketbleed",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        "https://filippo.io/ticketbleed"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_EARLY_CCS,
                        "Vulnerable to CCS injection / Early CCS",
                        "Evaluates whether the server is vulnerable to CCS injection / Early CCS",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to CCS injection / Early CCS",
                                "There is a vulnerability in your implementation. Update your software or contact the developers."),
                        "http://ccsinjection.lepidum.co.jp/blog/2014-06-05/CCS-Injection-en/index.html"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_CRIME,
                        "Vulnerable to CRIME",
                        "Evaluates whether the server is vulnerable to CRIME",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to CRIME",
                                "Disable TLS compression"),
                        "https://www.ekoparty.org/archive/2012/CRIME_ekoparty2012.pdf",
                        "https://www.iacr.org/cryptodb/data/paper.php?pubkey=3091"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_BREACH,
                        "Vulnerable to BREACH",
                        "Evaluates whether the server is vulnerable to BREACH",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to BREACH",
                                "Disable HTTP compression"),
                        "http://breachattack.com"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_LOGJAM,
                        "Vulnerable to Logjam",
                        "Evaluates whether the server is vulnerable to Logjam",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to Logjam",
                                "Disable export cipher suites and short Diffie-Hellman groups. Use at least 2048-bit Diffie-Hellman keys."),
                        "https://weakdh.org"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_FREAK,
                        "Vulnerable to FREAK",
                        "Evaluates whether the server is vulnerable to FREAK",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to FREAK",
                                "Disable export cipher suites."),
                        "https://www.smacktls.com/smack.pdf"));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V1,
                        "Vulnerable to the renegotiation attack (cs)",
                        "Evaluates whether the server is vulnerable to the renegotiation attack (cs)",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to the renegotiation attack (cs)",
                                "Disable insecure renegotiation."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_CIPHERSUITE_V2,
                        "Vulnerable to the renegotiation attack (cs)",
                        "Evaluates whether the server is vulnerable to the renegotiation attack (cs)",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to the renegotiation attack (cs)",
                                "Disable insecure renegotiation."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V1,
                        "Vulnerable to the renegotiation attack (ext)",
                        "Evaluates whether the server is vulnerable to the renegotiation attack (ext)",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to the renegotiation attack (ext)",
                                "Disable insecure renegotiation."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.VULNERABLE_TO_RENEGOTIATION_ATTACK_EXTENSION_V2,
                        "Vulnerable to the renegotiation attack (ext)",
                        "Evaluates whether the server is vulnerable to the renegotiation attack (ext)",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server is vulnerable to the renegotiation attack (ext)",
                                "Disable insecure renegotiation."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.MISSES_MAC_APPDATA_CHECKS,
                        "Misses Application message MAC check",
                        "Evaluates whether the server correctly validates the Application message MACs",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server does not verify MACs in Application messages",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.MISSES_MAC_FINISHED_CHECKS,
                        "Misses Finished message MAC check",
                        "Evaluates whether the server correctly validates the Finished message MAC",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server does not verify the Finished message MAC",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.MISSES_VERIFY_DATA_CHECKS,
                        "Misses verify data verification in the Finished messages",
                        "Evaluates whether the server correctly validates the verify data in the Finished messages",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server does not correctly process verify data in the Finished messages",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.MISSES_GCM_CHECKS,
                        "Misses GCM authentication tag check",
                        "Evaluates whether the server correctly validates the AES-GCM authentication tags",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server does not verify the AES-GCM authentication tags",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        ""));

        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_WEAK_RANDOMNESS,
                        "Uses weak randomness",
                        "Evaluates whether the server uses weak random values",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server uses weak random values",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.REUSES_EC_PUBLICKEY,
                        "Reuses ephemeral elliptic curve Diffie-Hellman keys",
                        "Evaluates whether the server reuses ephemeral elliptic curve keys transported in the ServerKeyExchange message",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server reuses ephemeral elliptic curve keys",
                                "Configure your server to always use fresh elliptic curve keys"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.REUSES_DH_PUBLICKEY,
                        "Reuses ephemeral Diffie-Hellman keys",
                        "Evaluates whether the server reuses ephemeral Diffie-Hellman keys transported in the ServerKeyExchange message",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server reuses ephemeral Diffie-Hellman keys",
                                "Configure your server to always use fresh Diffie-Hellman keys"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.REUSES_GCM_NONCES,
                        "Reuses GCM nonces",
                        "Evaluates whether the server reuses GCM nonces and is vulnerable to nonce-reuse attacks",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server reuses GCM nonces and is vulnerable to nonce-reuse attacks",
                                "There is a critical vulnerability in your implementation. Update your software or contact the developers."),
                        "https://eprint.iacr.org/2016/475"));

        // TODO: Need to be completed.
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.REQUIRES_SNI,
                        "SNI requirement",
                        "Evaluates whether the server requires the client to send a Server Name Indication (SNI) extension",
                        ""));

        // certificate issues
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_CERTIFICATE_ISSUES,
                        "Certificate issues",
                        "",
                        new PropertyResultRecommendation(TestResults.TRUE, "", ""),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.STRICT_ALPN,
                        "Strict ALPN",
                        "Evaluated whether the server rejects unsupported ALPN Strings. This is important to mitigate the ALPACA attacks",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "The server does not reject unsupported ALPN Strings",
                                "If possible configure your server to use strict ALPN verification"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.STRICT_SNI,
                        "Strict SNI",
                        "Evaluated whether the server rejects invalid SNI names. This is important to mitigate the ALPACA attacks",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "The server does not reject invalid SNI names",
                                "If possible configure your server to use strict SNI verification"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.ALPACA_MITIGATED,
                        "ALPACA Mitigation",
                        "Evaluated whether the server is vulnerable to ALPACA",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "The server does not reject invalid SNI names",
                                "If possible configure your server to use strict SNI and strict ALPN verification"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION,
                        "Supports DTLS fragmentation",
                        "Evaluates whether the server support the handshake message fragmentation",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "The server does not process fragmented handshake messages",
                                "Configure your server to process fragmented handshake messages"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_DTLS_FRAGMENTATION_WITH_INDIVIDUAL_PACKETS,
                        "Supports DTLS fragmentation",
                        "Evaluates whether the server support the handshake message fragmentation with individual transport packets",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "The server does not process fragmented handshake messages with individual transport packets",
                                "Configure your server to process fragmented handshake messages"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.SUPPORTS_REORDERING,
                        "Supports DTLS Reordering",
                        "Evaluates whether the server support message reordering",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "The server does not process message reordering",
                                "Configure your server to always process message reordering"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.PROCESSES_RETRANSMISSIONS,
                        "Processes DTLS retransmissions",
                        "Evaluates whether the server processes retransmissions",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "The server does not process retransmissions",
                                "Configure your server to always process retransmissions"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.HAS_COOKIE_CHECKS,
                        "Has cookie checks",
                        "Evaluates whether the server verify the cookie values",
                        new PropertyResultRecommendation(
                                TestResults.FALSE,
                                "The server does not reject invalid cookie values",
                                "Configure your server to always verify the cookie values"),
                        ""));
        recommendations.add(
                new Recommendation(
                        TlsAnalyzedProperty.MISSES_MESSAGE_SEQUENCE_CHECKS,
                        "Misses message sequence number checks",
                        "Evaluates whether the server verify the message sequence numbers",
                        new PropertyResultRecommendation(
                                TestResults.TRUE,
                                "The server does not verify the message sequence numbers",
                                "Configure your server to always verify the message sequence numbers"),
                        ""));
        RecommendationsIO recommendationsIO = new RecommendationsIO(TlsAnalyzedProperty.class);
        recommendationsIO.write(
                new File("src/main/resources/rating/recommendations.xml"),
                new Recommendations(recommendations));
        recommendationsIO.write(
                new File("src/main/resources/rating/recommendations_en.xml"),
                new Recommendations(recommendations));
    }
}
