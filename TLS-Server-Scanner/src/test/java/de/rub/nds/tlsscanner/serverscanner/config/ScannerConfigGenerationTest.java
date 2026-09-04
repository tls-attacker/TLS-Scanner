/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.config;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.ConfigIO;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Generates the config files in src/main/resources/configs from code, analogous to the config
 * generation in TLS-Attacker's ConfigTest. Everything that is derived from TLS-Attacker constants
 * (named groups, key share groups, TLS 1.3 cipher suites) is pulled from the respective enums, so
 * newly added constants end up in the generated configs on the next build.
 */
public class ScannerConfigGenerationTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final File RESOURCE_CONFIG_DIR = new File("src/main/resources/configs");

    /**
     * Resources are copied to the output directory before the tests run, so the freshly generated
     * config has to be placed there as well to make it part of the artifact of the current build.
     */
    private static final File OUTPUT_CONFIG_DIR = new File("target/classes/configs");

    /**
     * Signature and hash algorithms offered by the rich TLS 1.3 config. This list is deliberately
     * explicit: it contains the legacy and non-TLS-1.3 algorithms as well, since the config is used
     * to provoke a response from as many servers as possible.
     */
    private static final List<SignatureAndHashAlgorithm> RICH_SIGNATURE_AND_HASH_ALGORITHMS =
            Arrays.asList(
                    SignatureAndHashAlgorithm.ANONYMOUS_NONE,
                    SignatureAndHashAlgorithm.ANONYMOUS_MD5,
                    SignatureAndHashAlgorithm.ANONYMOUS_SHA1,
                    SignatureAndHashAlgorithm.ANONYMOUS_SHA224,
                    SignatureAndHashAlgorithm.ANONYMOUS_SHA256,
                    SignatureAndHashAlgorithm.ANONYMOUS_SHA384,
                    SignatureAndHashAlgorithm.ANONYMOUS_SHA512,
                    SignatureAndHashAlgorithm.RSA_NONE,
                    SignatureAndHashAlgorithm.RSA_MD5,
                    SignatureAndHashAlgorithm.RSA_SHA1,
                    SignatureAndHashAlgorithm.RSA_SHA224,
                    SignatureAndHashAlgorithm.RSA_SHA256,
                    SignatureAndHashAlgorithm.RSA_SHA384,
                    SignatureAndHashAlgorithm.RSA_SHA512,
                    SignatureAndHashAlgorithm.DSA_NONE,
                    SignatureAndHashAlgorithm.DSA_MD5,
                    SignatureAndHashAlgorithm.DSA_SHA1,
                    SignatureAndHashAlgorithm.DSA_SHA224,
                    SignatureAndHashAlgorithm.DSA_SHA256,
                    SignatureAndHashAlgorithm.DSA_SHA384,
                    SignatureAndHashAlgorithm.DSA_SHA512,
                    SignatureAndHashAlgorithm.ECDSA_NONE,
                    SignatureAndHashAlgorithm.ECDSA_MD5,
                    SignatureAndHashAlgorithm.ECDSA_SHA1,
                    SignatureAndHashAlgorithm.ECDSA_SHA224,
                    SignatureAndHashAlgorithm.ECDSA_SHA256,
                    SignatureAndHashAlgorithm.ECDSA_SHA384,
                    SignatureAndHashAlgorithm.ECDSA_SHA512,
                    SignatureAndHashAlgorithm.ED25519,
                    SignatureAndHashAlgorithm.ED448,
                    SignatureAndHashAlgorithm.SM2_SM3,
                    SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
                    SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
                    SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512,
                    SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256,
                    SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384,
                    SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512,
                    SignatureAndHashAlgorithm.GOSTR34102001_GOSTR3411,
                    SignatureAndHashAlgorithm.GOSTR34102012_256_GOSTR34112012_256,
                    SignatureAndHashAlgorithm.GOSTR34102012_512_GOSTR34112012_512);

    private Config config;

    @BeforeEach
    public void setUp() {
        this.config = new Config();
        stripConfig(config);
    }

    /** Updates src/main/resources/configs/tls13rich.config */
    @Test
    public void generateTls13RichConfig() {
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);
        config.setTls13BackwardsCompatibilityMode(true);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddRenegotiationInfoExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);

        /**
         * The rich config offers all SigHash algos and all groups, even those not permitted in TLS
         * 1.3. Ultimately, it is the server's responsibility to ensure they are not negotiated in
         * TLS 1.3 and this is something we want to evaluate in our probes.
         */
        config.setDefaultClientSupportedCipherSuites(CipherSuite.getImplementedTls13CipherSuites());
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                SignatureAndHashAlgorithm.getImplemented());
        config.setDefaultClientSupportedCompressionMethods(CompressionMethod.NULL);

        config.setDefaultClientNamedGroups(NamedGroup.getImplemented());
        config.setDefaultClientKeyShareNamedGroups(NamedGroup.getImplemented());

        writeConfig(config, "tls13rich.config");
    }

    private static void writeConfig(Config config, String fileName) {
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, fileName));
        if (OUTPUT_CONFIG_DIR.isDirectory()) {
            ConfigIO.write(config, new File(OUTPUT_CONFIG_DIR, fileName));
        }
    }

    /** Sets all non-final fields to null so that only explicitly set values end up in the file. */
    private static void stripConfig(Config config) {
        for (Field field : config.getClass().getDeclaredFields()) {
            try {
                if (!Modifier.isFinal(field.getModifiers())
                        && !Modifier.isStatic(field.getModifiers())) {
                    field.setAccessible(true);
                    field.set(config, null);
                }
            } catch (IllegalArgumentException | IllegalAccessException ex) {
                LOGGER.error("Could not strip config field {}", field.getName(), ex);
            }
        }
    }
}
