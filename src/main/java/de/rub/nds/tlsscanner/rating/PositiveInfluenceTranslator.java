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

/**
 *
 * @author ic0ns
 */
public class PositiveInfluenceTranslator {

    private PositiveInfluenceTranslator() {
    }

    public static String getInfluence(AnalyzedProperty constant) {
        switch (constant) {
            case SUPPORTS_SSL_2:
                return "You have SSlv2 disabled";
            case SUPPORTS_SSL_3:
                return "You have SSLv3 disabled";
            case SUPPORTS_TLS_1_0:
                return "You have TLS 1.0 disabled";
            case SUPPORTS_TLS_1_3:
                return "You have TLS 1.3 enabled";
            case SUPPORTS_TLS_1_3_DRAFT:
                return "You have disabled TLS 1.3 draft versions";
            case SUPPORTS_PFS:
                return "You are supporting PFS ciphersuites";
            case PREFERS_PFS:
                return "You are prefering PFS ciphersuites";
            case ENFORCES_PFS:
                return "You are enforcing PFS ciphersuites";
            case ENFOCRES_CS_ORDERING:
                return "You are enforcing the ciphersuite selection order server side";
            case SUPPORTS_NULL_CIPHERS:
                return "You have disabled NULL ciphersuites";
            case SUPPORTS_FORTEZZA:
                return "You have disabled FORTEZZA ciphersuites";
            case SUPPORTS_EXPORT:
                return "You have disabled EXPORT ciphersuites";
            case SUPPORTS_ANON:
                return "You have disabled anon ciphersuites";
            case SUPPORTS_DES:
                return "You have disabled DES ciphersuites";
            case SUPPORTS_IDEA:
                return "You have disabled IDEA ciphersuites";
            case SUPPORTS_RC2:
                return "You have disabled RC2 ciphersuites";
            case SUPPORTS_RC4:
                return "You have disabled RC4 ciphersuites";
            case SUPPORTS_CBC:
                return "You have disabled CBC ciphersuites";
            case SUPPORTS_AEAD:
                return "You have enabled AEAD ciphersuites";
            case SUPPORTS_EXTENDED_MASTER_SECRET:
                return "You have enabled the Extended Mastersecret Extension";
            case SUPPORTS_ENCRYPT_THEN_MAC:
                return "You have enabled the Encrypt Then Mac Extension";
            case SUPPORTS_MONTOGMERY_CURVES:
                return "You support Montgomery Curves";
            case SUPPORTS_SESSION_TICKETS:
                return "You support TLS-Session Tickets";
            case SUPPORTS_SECURE_RENEGOTIATION_EXTENSION:
                return "You support the Secure Renegotiation Extension";
            case SUPPORTS_TOKENBINDING:
                return "You support Tokenbinding";
            case SUPPORTS_TLS_COMPRESSION:
                return "You disabled TLS-Compression";
            case HAS_VERSION_INTOLERANCE:
            case HAS_CIPHERSUITE_INTOLERANCE:
            case HAS_EXTENSION_INTOLERANCE:
            case HAS_CIPHERSUITE_LENGTH_INTOLERANCE:
            case HAS_COMPRESSION_INTOLERANCE:
            case HAS_ALPN_INTOLERANCE:
            case HAS_CLIENT_HELLO_LENGTH_INTOLERANCE:
            case HAS_EMPTY_LAST_EXTENSION_INTOLERANCE:
            case HAS_SIG_HASH_ALGORITHM_INTOLERANCE:
            case HAS_BIG_CLIENT_HELLO_INTOLERANCE:
            case HAS_SECOND_CIPHERSUITE_BYTE_BUG:
            case IGNORES_OFFERED_CIPHERSUITES:
            case REFLECTS_OFFERED_CIPHERSUITES:
            case IGNORES_OFFERED_NAMED_GROUPS:
            case IGNORES_OFFERED_SIG_HASH_ALGOS:
                return constant.name();
            case VULNERABLE_TO_BLEICHENBACHER:
                return "You are not vulnerable to the Bleichenbacher Attack";
            case VULNERABLE_TO_CBC_PADDING_ORACLE:
                return "You are not vulnerable to the PaddingOracle Attack";
            case SUPPORTS_HTTP_COMPRESSION:
                return "You have disabled HTTP-Compression. You are not vulnerable to the BREACH attack";
            case VULNERABLE_TO_INVALID_CURVE:
                return "You are not vulnerable to the InvalidCurve attack";
            case VULNERABLE_TO_INVALID_CURVE_EPHEMERAL:
                return "You are not vulnerable to the InvalidCurve (ephemeral) attack";
            case VULNERABLE_TO_INVALID_CURVE_EPHEMERAL_WITH_REUSE:
                return "You are not vulnerable to the InvalidCurve (ephemeral with pk reuse) attack";
            case VULNERABLE_TO_POODLE:
                return "You are not vulnerable to the POODLE attack";
            case VULNERABLE_TO_TLS_POODLE:
                return "You are not vulnerable to the TLS-POODLE attack";
            case VULNERABLE_TO_SWEET_32:
                return "You do not support 64-bit Ciphersuites";
            case VULNERABLE_TO_DROWN:
                return "You are not vulnerable to the DROWN attack";
            case VULNERABLE_TO_HEARTBLEED:
                return "You are not vulnerable to the Heartbleed attack";
            case VULNERABLE_TO_EARLY_CCS:
                return "You are not vulnerable to the EarlyCcs attack";
            case MISSES_MAC_APPDATA_CHECKS:
                return "You are checking the MAC of ApplicationData correctly";
            case MISSES_CHECKS_MAC_FINISHED_CHECKS:
                return "You are checking the MAC of the Finished message correctly";
            case MISSES_CHECKS_VERIFY_DATA_CHECKS:
                return "You are checking the verify_data of the finished message correctly";
            case HAS_CERTIFICATE_ISSUES:
                return "Your certificate chain does not have any issues";
            case SUPPORTS_INSECURE_RENEGOTIATION:
                return "You are not allowing insecure renegotiation";
            case SUPPORTS_RENEGOTIATION:
                return "You are not allowing renegotiation at all";
            case SUPPORTS_HSTS:
                return "You are supporting HSTS";
            case SUPPORTS_HPKP_REPORTING:
                return "You are supporting HPKP";
            case HAS_WEAK_RANDOMNESS:
                return "Your implementation does not use Duplicate Nonces";
            case REUSES_EC_PUBLICKEY:
                return "You are not reusing EC public keys";
            case REUSES_DH_PUBLICKEY:
                return "You are not reusing DH public keys";
            case SUPPORTS_COMMON_DH_PRIMES:
                return "You are not using common DH primes";
            case SUPPORTS_PRIME_MODULI:
                return "You are using a prime moduli";
            case SUPPORTS_SAFEPRIME_MODULI:
                return "You are using a safe-prime moduli";
            default:
                return "UNKNOWN";
        }
    }
}
