/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.selector;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class ConfigSelector {

    private ConfigSelector() {
    }

    public static Config getNiceConfig(ScannerConfig scannerConfig) {
        Config config = scannerConfig.createConfig();
        config.setAddECPointFormatExtension(Boolean.TRUE);
        config.setAddEllipticCurveExtension(Boolean.TRUE);
        config.setAddServerNameIndicationExtension(Boolean.TRUE);
        config.setAddSignatureAndHashAlgorithmsExtension(Boolean.TRUE);
        config.setAddRenegotiationInfoExtension(Boolean.TRUE);
        config.setDefaultClientSupportedCiphersuites(CipherSuite.values());
        config.getDefaultClientSupportedCiphersuites().remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        config.getDefaultClientSupportedCiphersuites().remove(CipherSuite.TLS_FALLBACK_SCSV);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        List<SignatureAndHashAlgorithm> sigHashList = new LinkedList<>();
        sigHashList.addAll(Arrays.asList(SignatureAndHashAlgorithm.values()));
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(sigHashList);
        config.setDefaultClientSupportedCompressionMethods(CompressionMethod.NULL, CompressionMethod.LZS,
                CompressionMethod.DEFLATE);
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterFatal(true);
        // cleanupConfig(config);
        return config;
    }

    public static Config cleanupConfig(Config config) {
        boolean hasEcCipherSuite = false;
        for (CipherSuite suite : config.getDefaultClientSupportedCiphersuites()) {
            if (suite.name().toUpperCase().contains("_EC")) {
                hasEcCipherSuite = true;
            }
        }
        config.setAddEllipticCurveExtension(hasEcCipherSuite);
        config.setAddECPointFormatExtension(hasEcCipherSuite);
        return config;
    }
}
