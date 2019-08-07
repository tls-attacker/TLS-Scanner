/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import de.rub.nds.tlsscanner.report.AnalyzedProperty;
import java.io.File;
import java.util.LinkedList;
import java.util.List;
import org.junit.Test;

public class DefaultRecommendationsTest {

    @Test
    public void createDefaultRatingInfluencers() {
        List<Recommendation> recommendations = new LinkedList<>();

        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SSL_2, "SSL 2.0 support",
                "Evaluates whether the SSL 2.0 protocol is supported",
                new PropertyResultRecommendation(TestResult.TRUE, "SSL 2.0 is enabled", "Disable SSL 2.0", ""),
                "https://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html", "https://drownattack.com"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SSL_3, "SSL 3.0 support",
                "Evaluates whether the SSL 3.0 protocol is supported",
                new PropertyResultRecommendation(TestResult.TRUE, "SSL 3.0 is enabled", "Disable SSL 3.0"),
                "https://tools.ietf.org/html/rfc6101", "https://www.openssl.org/~bodo/ssl-poodle.pdf"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_TLS_1_0, "TLS 1.0 support",
                "Evaluates whether the TLS 1.0 protocol is supported",
                new PropertyResultRecommendation(TestResult.TRUE, "TLS 1.0 is enabled", "Consider disabling TLS 1.0", ""),
                "https://www.ietf.org/rfc/rfc2246"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_TLS_1_1, "TLS 1.1 support",
                "Evaluates whether the TLS 1.1 protocol is supported",
                new PropertyResultRecommendation(TestResult.TRUE, "TLS 1.1 is enabled", "Consider disabling TLS 1.1", ""),
                "https://www.ietf.org/rfc/rfc4346"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_TLS_1_2, "TLS 1.2 support",
                "Evaluates whether the TLS 1.2 protocol is supported",
                new PropertyResultRecommendation(TestResult.FALSE, "TLS 1.2 is disabled", "Enable TLS 1.2"),
                "https://www.ietf.org/rfc/rfc5246.txt"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_TLS_1_3, "TLS 1.3 support",
                "Evaluates whether the TLS 1.3 protocol is supported",
                new PropertyResultRecommendation(TestResult.FALSE, "TLS 1.3 is disabled", "Enable TLS 1.3"),
                "https://tools.ietf.org/html/rfc8446"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_TLS_1_3_DRAFT, "TLS 1.3 draft version support",
                "Evaluates whether a TLS 1.3 version draft is supported",
                new PropertyResultRecommendation(TestResult.TRUE, "TLS 1.3 draft version is enabled", "Update your server and enable the TLS 1.3 final version"),
                "https://tools.ietf.org/html/rfc8446"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_DTLS_1_0, "DTLS 1.0 support",
                "Evaluates whether the DTLS 1.0 protocol is supported",
                new PropertyResultRecommendation(TestResult.TRUE, "DTLS 1.0 is enabled", "Disable DTLS 1.0, it is a UDP protocol"),
                "https://tools.ietf.org/html/rfc4347"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_DTLS_1_2, "DTLS 1.2 support",
                "Evaluates whether the DTLS 1.2 protocol is supported",
                new PropertyResultRecommendation(TestResult.TRUE, "DTLS 1.2 is enabled", "Disable DTLS 1.2, it is a UDP protocol"),
                "https://tools.ietf.org/html/rfc6347"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_DTLS_1_3, "DTLS 1.3 support",
                "Evaluates whether the DTLS 1.3 protocol is supported",
                new PropertyResultRecommendation(TestResult.TRUE, "DTLS 1.3 is enabled", "Disable DTLS 1.3, it is a UDP protocol"),
                ""));
        
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_NULL_CIPHERS, "Null cipher support",
                "Evaluates whether the TLS server supports null ciphers",
                new PropertyResultRecommendation(TestResult.TRUE, "Null ciphers are supported", "Disable insecure null ciphers"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_FORTEZZA, "Fortezza support",
                "Evaluates whether the TLS server supports Fortezza ciphers",
                new PropertyResultRecommendation(TestResult.TRUE, "Fortezza ciphers are supported", "Disable Fortezza cipher suites", "Fortezza cipher suittes were developed by NSA in the 90s. You should better get rid of Fortezza algorithms."),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_EXPORT, "Export cipher support",
                "Evaluates whether the TLS server supports export ciphers",
                new PropertyResultRecommendation(TestResult.TRUE, "Export ciphers are enabled", "Disable export ciphers", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_ANON, "Anonymous cipher support",
                "Evaluates whether the TLS server supports anonymous ciphers",
                new PropertyResultRecommendation(TestResult.TRUE, "Anonymous ciphers are enabled", "Disable anonymous ciphers"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_DES, "DES support",
                "Evaluates whether the TLS server supports DES ciphers",
                new PropertyResultRecommendation(TestResult.TRUE, "DES ciphers are enabled", "Disable DES ciphers"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_3DES, "3DES (Triple DES) support",
                "Evaluates whether the TLS server supports 3DES (Triple DES) ciphers",
                new PropertyResultRecommendation(TestResult.TRUE, "3DES ciphers are enabled", "Disable 3DES ciphers"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SEED, "SEED cipher support",
                "Evaluates whether the TLS server supports SEED ciphers",
                "SEED is a 128 bit block cipher developed by the KISA (Korea Information Security Agency) in 1998",
                "https://tools.ietf.org/html/rfc4162"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_IDEA, "IDEA cipher support",
                "Evaluates whether the TLS server supports IDEA ciphers",
                "IDEA (International Data Encryption Algorithm) is a block cipher. It uses a 128 bit key and operates on 64 bit blocks.",
                new PropertyResultRecommendation(TestResult.TRUE, "IDEA ciphers are enabled", "Disable IDEA ciphers"),
                "https://tools.ietf.org/html/rfc5469"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_RC2, "RC2 cipher support",
                "Evaluates whether the TLS server supports RC2 ciphers",
                "RC2 is a 64 bit block cipher designed by Ron Rivest in 1987",
                new PropertyResultRecommendation(TestResult.TRUE, "RC2 ciphers are enabled", "Disable RC2 ciphers"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_RC4, "RC4 cipher support",
                "Evaluates whether the TLS server supports RC4 ciphers",
                "RC4 is a stream cipher designed by Ron Rivest in 1987",
                new PropertyResultRecommendation(TestResult.TRUE, "RC4 ciphers are enabled", "Disable RC4 ciphers"),
                "https://tools.ietf.org/html/rfc7465", "https://www.rc4nomore.com/"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_CBC, "CBC cipher suite support",
                "Evaluates whether the TLS server supports CBC cipher suites",
                new PropertyResultRecommendation(TestResult.TRUE, "CBC cipher suites are enabled", "Disable CBC cipher suites"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_AEAD, "AEAD cipher suites support",
                "Evaluates whether the TLS server supports AEAD (Authenticated Encryption with Associated Data) cipher suites, e.g., AES-GCM",
                new PropertyResultRecommendation(TestResult.FALSE, "AEAD cipher suites are disabled", "Enable AEAD cipher suites, e.g., AES-GCM"),
                ""));
        
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_PFS, "Perfect Forward Secrecy (PFS) support",
                "Evaluates whether the TLS server supports Perfect Forward Secrecy (PFS)",
                new PropertyResultRecommendation(TestResult.FALSE, "PFS is not supported", "Enable perfect forward secure cipher suites, e.g., TLS-DHE or TLS-ECDHE"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_PFS, "Support for only PFS cipher suites",
                "Evaluates whether the TLS server exclusively supports Perfect Forward Secrecy (PFS)",
                new PropertyResultRecommendation(TestResult.FALSE, "Not all cipher suites are perfect forward secure", "Consider disabling cipher suites which are not perfect forward secure. Enable only perfect forward secure cipher suites, e.g., TLS-DHE or TLS-ECDHE"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_AES, "AES cipher support",
                "Evaluates whether the TLS server supports AES cipher",
                new PropertyResultRecommendation(TestResult.FALSE, "AES cipher suites are disabled", "Enable AES cipher suites"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_CAMELLIA, "Camellia cipher support",
                "Evaluates whether the TLS server supports Camellia cipher",
                "Camellia is a 128 bit block cipher designed by Mitsubishi and NTT in 2000",
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_ARIA, "ARIA cipher support",
                "Evaluates whether the TLS server supports ARIA cipher",
                "ARIA is a 128 bit block cipher designed in 2003",
                "https://tools.ietf.org/html/rfc5794"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_CHACHA, "ChaCha cipher support",
                "Evaluates whether the TLS server supports ChaCha cipher",
                new PropertyResultRecommendation(TestResult.FALSE, "ChaCha cipher is disabled", "Enable ChaCha cipher"),
                "https://tools.ietf.org/html/rfc7905"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_RSA, "RSA key exchange support",
                "Evaluates whether the TLS server supports RSA key exchange",
                new PropertyResultRecommendation(TestResult.TRUE, "RSA key exchange is enabled", "Disable RSA key exchange"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_DH, "Diffie-Hellman (DH) key exchange support",
                "Evaluates whether the TLS server supports Diffie-Hellman (DH) key exchange",
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_ECDH, "Elliptic Curve Diffie-Hellman (ECDH) key exchange support",
                "Evaluates whether the TLS server supports Elliptic Curve Diffie-Hellman (ECDH) key exchange",
                new PropertyResultRecommendation(TestResult.FALSE, "Elliptic Curve Diffie-Hellman (ECDH) key exchange is disabled", "Enable Elliptic Curve Diffie-Hellman (ECDH)"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_STATIC_ECDH, "Static Elliptic Curve Diffie-Hellman (ECDH) key exchange support",
                "Evaluates whether the TLS server supports static Elliptic Curve Diffie-Hellman (ECDH) key exchange",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "Static Elliptic Curve Diffie-Hellman (ECDH) key exchange is enabled", "Disable static Elliptic Curve Diffie-Hellman (ECDH)"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_GOST, "GOST cipher support",
                "Evaluates whether the TLS server supports GOST cipher",
                "GOST is a block cipher designed in the USSR in the nineties. It has a block size of 64 bits. ",
                new PropertyResultRecommendation(TestResult.TRUE, "GOST ciphers are enabled", "Disable GOST ciphers"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SRP, "Secure Remote Password (SRP) support",
                "Evaluates whether the TLS server supports Secure Remote Password (SRP) cipher suites",
                "https://tools.ietf.org/html/rfc5054"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_KERBEROS, "Kerberos cipher suites support",
                "Evaluates whether the TLS server supports Kerberos cipher suites",
                "https://tools.ietf.org/html/rfc2712"));
        
        // todo psk cipher suites
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_PSK_PLAIN, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_PSK_RSA, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_PSK_DHE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_PSK_ECDHE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        
        // post quantum
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_POST_QUANTUM, "Post quantum algorithms support",
                "Evaluates whether the TLS server supports post quantum algorithms",
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_NEWHOPE, "Post quantum new hope algorihtm support",
                "Evaluates whether the TLS server supports the new hope post quantum algorithm",
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_ECMQV, "Post quantum ECMQV algorithm support",
                "Evaluates whether the TLS server supports the ECMQV post quantum algorithm",
                ""));
        
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_STREAM_CIPHERS, "Stream cipher support",
                 "Evaluates whether the TLS server supports stream ciphers",
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_BLOCK_CIPHERS, "Block cipher support",
                 "Evaluates whether the TLS server supports block ciphers",
                ""));

        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_EXTENDED_MASTER_SECRET, "Extended master secret support",
                "Evaluates whether the TLS server supports extended master secret extension",
                new PropertyResultRecommendation(TestResult.FALSE, "Extended master secret extension is not supported", "Enable support for the extended master secret"),
                "https://tools.ietf.org/html/rfc7627"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_ENCRYPT_THEN_MAC, "Encrypt-then-MAC extension support",
                "Evaluates whether the TLS server supports Encrypt-then-MAC extension",
                new PropertyResultRecommendation(TestResult.FALSE, "Encrypt-then-MAC extension is not supported", "Enable support for the Encrypt-then-MAC"),
                "https://tools.ietf.org/html/rfc7366"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_TOKENBINDING, "Token binding support",
                "Evaluates whether the TLS server supports token binding",
                ""));
        
        
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_MONTOGMERY_CURVES, "Montgomery curve support",
                "",
                ""));
        
        // session resumption
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SESSION_TICKETS, "Support for session resumption with session tickets",
                "Evaluates whether the TLS server supports session resumption with session tickets",
                new PropertyResultRecommendation(TestResult.FALSE, "Session tickets are disabled", "Enable session resumption with session tickets"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SESSION_IDS, "Support for session resumption with session IDs",
                "Evaluates whether the TLS server supports session resumption with session IDs",
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SESSION_TICKETS_ROTATED, "Support for rotated session tickets",
                "Evaluates whether the TLS server supports session resumption with session tickets whose keys are being rotated",
                "Session tickets are created with symmetric keys. The lifetime of the symmetric keys used for session tickets should be restricted to reduce the attack surface. The ticket lifetime is typically indicated in the ticket lifetime hint.",
                new PropertyResultRecommendation(TestResult.FALSE, "Session resumption with rotating session tickets is disabled", "Frequently changing session ticket keys improves the security, enable rotated session tickets."),
                ""));
        
        // session renegotiation
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_RENEGOTIATION, "TLS renegoatiation support",
                "Evaluates whether the TLS server supports renegotiation.",
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_INSECURE_RENEGOTIATION, "TLS insecure renegoatiation support",
                "Evaluates whether the TLS server supports renegotiation.",
                new PropertyResultRecommendation(TestResult.TRUE, "Insecure renegotiation is enabled", "Disable renegotiation or enable only secure renegotiation."),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SECURE_RENEGOTIATION_EXTENSION, "Support for secure renegotiation extension",
                "Evaluates whether the TLS server supports secure renegotiation extension.",
                "https://tools.ietf.org/html/rfc5746"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_SECURE_RENEGOTIATION, "Support for client-side secure renegotiation",
                "Evaluates whether the TLS server supports client-side secure renegotiation.",
                "TLS secure renegotiation can be started by the client as well as by the server. In its configuration the server can restrict the support for the server-side secure renegotiation. In that case, only the server can start the renegotiation process.",
                "https://tools.ietf.org/html/rfc5746"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_CLIENT_SIDE_INSECURE_RENEGOTIATION, "Support for client-side insecure renegotiation",
                "Evaluates whether the TLS server supports client-side insecure renegotiation.",
                new PropertyResultRecommendation(TestResult.TRUE, "Insecure renegotiation is enabled", "Disable renegotiation or enable only secure renegotiation."),
                "https://tools.ietf.org/html/rfc5746"));
        
        
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_TLS_FALLBACK_SCSV, "TLS Fallback Signaling Cipher Suite Value (SCSV) support",
                "Evaluates whether the TLS server supports TLS Fallback Signaling Cipher Suite Value (SCSV)",
                "In order to establish the highest possible TLS version, TLS clients attempt to perform several TLS handshake starting with the one with the highetst version. If a TLS handshake with a particular version does not work, the TLS client attampts to execute the handshake with a lower version. This of course allows an attacker to downgrade the TLS connection. TLS Fallback Signaling Cipher Suite Value (SCSV) was introduced to prevent downgrade attacks. For example, if a TLS client attempts to establish a TLS 1.1 conenction after an unsuccessful TLS 1.2 handshake attempt, it includes a TLS SCSV cipher suite into the ClientHello message. The server accepts this handshake if and only if its highest version is TLS 1.1.",
                new PropertyResultRecommendation(TestResult.TRUE, "TLS SCSV is disabled", " Enable TLS Fallback Signaling Cipher Suite Value (SCSV)"),
                "https://tools.ietf.org/html/rfc7507"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_TLS_COMPRESSION, "TLS compression support",
                "Evaluates whether the TLS server supports TLS compresssion",
                new PropertyResultRecommendation(TestResult.TRUE, "TLS compression is supported", "Disable TLS compression"),
                ""));
        
        //todo DH
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_COMMON_DH_PRIMES, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_PRIME_MODULI, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_SAFEPRIME_MODULI, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        
        // HTTP
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_HTTPS, "HTTPS support",
                "",
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_HSTS, "Support for HTTP Strict Transport Security (HSTS)",
                "Evaluates whether the TLS server supports HTTP Strict Transport Security (HSTS)",
                new PropertyResultRecommendation(TestResult.FALSE, "HSTS is disabled", "Enable HSTS"),
                "https://tools.ietf.org/html/rfc6797"));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_HSTS_PRELOADING, "Support for HTTP Strict Transport Security (HSTS) preloading",
                "",
                new PropertyResultRecommendation(TestResult.FALSE, "HSTS is disabled", "Enable HSTS"),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_HPKP, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_HPKP_REPORTING, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.SUPPORTS_HTTP_COMPRESSION, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.PREFERS_PFS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.ENFORCES_PFS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.ENFOCRES_CS_ORDERING, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_VERSION_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_CIPHERSUITE_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_EXTENSION_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_CIPHERSUITE_LENGTH_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_COMPRESSION_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_ALPN_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_CLIENT_HELLO_LENGTH_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_EMPTY_LAST_EXTENSION_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_SIG_HASH_ALGORITHM_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_BIG_CLIENT_HELLO_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_NAMED_GROUP_INTOLERANCE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_SECOND_CIPHERSUITE_BYTE_BUG, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.REFLECTS_OFFERED_CIPHERSUITES, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.IGNORES_OFFERED_CIPHERSUITES, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.IGNORES_OFFERED_NAMED_GROUPS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.IGNORES_OFFERED_SIG_HASH_ALGOS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_BLEICHENBACHER, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_PADDING_ORACLE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_CBC_PADDING_ORACLE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_WITH_REUSE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_POODLE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_TLS_POODLE, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_SWEET_32, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_DROWN, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_HEARTBLEED, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_TICKETBLEED, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_EARLY_CCS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_CRIME, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_BREACH, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_LOGJAM, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_FREAK, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.VULNERABLE_TO_CVE20162107, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.MISSES_MAC_APPDATA_CHECKS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.MISSES_CHECKS_MAC_FINISHED_CHECKS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.MISSES_CHECKS_VERIFY_DATA_CHECKS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.MISSES_GCM_CHECKS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_CERTIFICATE_ISSUES, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.HAS_WEAK_RANDOMNESS, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.REUSES_EC_PUBLICKEY, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.REUSES_DH_PUBLICKEY, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.REUSES_GCM_NONCES, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));
        recommendations.add(new Recommendation(AnalyzedProperty.REQUIRES_SNI, "",
                "",
                new PropertyResultRecommendation(TestResult.TRUE, "", ""),
                ""));

        RatingIO.writeRecommendations(new Recommendations(recommendations),
                new File("src/main/resources/" + Recommendations.DEFAULT_RECOMMENDATIONS_FILE));
    }
}
