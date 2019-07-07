/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

/**
 *
 * @author ic0ns
 */
public class PositiveInfluenceTranslator {

    private PositiveInfluenceTranslator() {
    }

    public static String getInfluence(AnalyzedProperty constant) {
        switch (constant) {
            case SSL_2:
                return "You have SSlv2 disabled";
            case SSL_3:
                return "You have SSLv3 disabled";
            case TLS_1_0:
                return "You have TLS 1.0 disabled";
            case TLS_1_3:
                return "You have TLS 1.3 enabled";
            case TLS_1_3_DRAFT:
                return "You have disabled TLS 1.3 draft versions";
            case SUPPORT_PFS:
                return "You are supporting PFS ciphersuites";
            case PREFER_PFS:
                return "You are prefering PFS ciphersuites";
            case ENFORCE_PFS:
                return "You are enforcing PFS ciphersuites";
            case ENFOCRE_CS_ORDERING:
                return "You are enforcing the ciphersuite selection order server side";
            case NULL_CIPHERS:
                return "You have disabled NULL ciphersuites";
            case FORTEZZA:
                return "You have disabled FORTEZZA ciphersuites";
            case EXPORT:
                return "You have disabled EXPORT ciphersuites";
            case ANON:
                return "You have disabled anon ciphersuites";
            case DES:
                return "You have disabled DES ciphersuites";
            case IDEA:
                return "You have disabled IDEA ciphersuites";
            case RC2:
                return "You have disabled RC2 ciphersuites";
            case RC4:
                return "You have disabled RC4 ciphersuites";
            case CBC:
                return "You have disabled CBC ciphersuites";
            case SUPPORT_AEAD:
                return "You have enabled AEAD ciphersuites";
            case SUPPORT_EXTENDED_MASTER_SECRET:
                return "You have enabled the Extended Mastersecret Extension";
            case SUPPORT_ENCRYPT_THEN_MAC:
                return "You have enabled the Encrypt Then Mac Extension";
            case SUPPORT_MONTOGMERY_CURVES:
                return "You support Montgomery Curves";
            case SUPPORT_SESSION_TICKETS:
                return "You support TLS-Session Tickets";
            case SUPPORT_SECURE_RENEGOTIATION_EXTENSION:
                return "You support the Secure Renegotiation Extension";
            case SUPPORT_TOKENBINDING:
                return "You support Tokenbinding";
            case TLS_COMPRESSION:
                return "You disabled TLS-Compression";
            case VERSION_INTOLERANCES:
            case CIPHERSUITE_INTOLERANCES:
            case EXTENSION_INTOLERANCES:
            case CIPHERSUITE_LENGTH_INTOLERANCES:
            case COMPRESSION_INTOLERANCES:
            case ALPN_INTOLERANCES:
            case CLIENTHELLO_LENGTH_INTOLERANCES:
            case EMPTY_LAST_EXTENSION_INTOLERANCES:
            case SIG_HASH_ALGORITHM_INTOLERANCES:
            case BIG_CLIENT_HELLO_INTOLERANCES:
            case SECOND_CIPHERSUITE_BYTE_BUG:
            case IGNORES_OFFERED_CIPHERSUITES:
            case REFLECTS_OFFERED_CIPHERSUITES:
            case IGNORES_OFFERED_NAMEDGROUPS:
            case IGNORES_OFFERED_SIG_HASH_ALGOS:
                return constant.name();
            case BLEICHENBACHER:
                return "You are not vulnerable to the Bleichenbacher Attack";
            case CBC_PADDING_ORACLE:
                return "You are not vulnerable to the PaddingOracle Attack";
            case HTTP_COMPRESSION:
                return "You have disabled HTTP-Compression. You are not vulnerable to the BREACH attack";
            case INVALID_CURVE:
                return "You are not vulnerable to the InvalidCurve attack";
            case INVALID_CURVE_EPHEMERAL:
                return "You are not vulnerable to the InvalidCurve (ephemeral) attack";
            case INVALID_CURVE_EPHEMERAL_WITH_REUSE:
                return "You are not vulnerable to the InvalidCurve (ephemeral with pk reuse) attack";
            case POODLE:
                return "You are not vulnerable to the POODLE attack";
            case TLS_POODLE:
                return "You are not vulnerable to the TLS-POODLE attack";
            case SHORT_64_BIT_CIPHERSUITE:
                return "You do not support 64-bit Ciphersuites";
            case DROWN:
                return "You are not vulnerable to the DROWN attack";
            case HEARTBLEED:
                return "You are not vulnerable to the Heartbleed attack";
            case EARLY_CCS:
                return "You are not vulnerable to the EarlyCcs attack";
            case MISSING_CHECKS_MAC_APPDATA:
                return "You are checking the MAC of ApplicationData correctly";
            case MISSING_CHECKS_MAC_FINISHED:
                return "You are checking the MAC of the Finished message correctly";
            case MISSING_CHECKS_VERIFY_DATA:
                return "You are checking the verify_data of the finished message correctly";
            case CERTIFICATE_ISSUES:
                return "Your certificate chain does not have any issues";
            case INSECURE_RENEGOTIATION:
                return "You are not allowing insecure renegotiation";
            case RENEGOTIATION:
                return "You are not allowing renegotiation at all";
            case SUPPORT_HSTS:
                return "You are supporting HSTS";
            case SUPPORT_HPKP_REPORTING:
                return "You are supporting HPKP";
            case WEAK_RANDOMNESS:
                return "Your implementation does not use Duplicate Nonces";
            case EC_PUBLICKEY_REUSE:
                return "You are not reusing EC public keys";
            case DH_PUBLICKEY_REUSE:
                return "You are not reusing DH public keys";
            case COMMON_DH_PRIMES:
                return "You are not using common DH primes";
            case SUPPORT_PRIME_MODULI:
                return "You are using a prime moduli";
            case SUPPORT_SAFEPRIME_MODULI:
                return "You are using a safe-prime moduli";
            default:
                return "UNKNOWN";
        }
    }
}
