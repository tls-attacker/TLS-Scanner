/**
 * TLS-Server-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsscanner.serverscanner.selector;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsscanner.serverscanner.config.ScannerConfig;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

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
        List<CipherSuite> filteredCipherSuites =
            Arrays.asList(CipherSuite.values()).stream()
                .filter(cipherSuite -> !cipherSuite.isGrease()
                    && cipherSuite != CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                    && cipherSuite != CipherSuite.TLS_FALLBACK_SCSV)
                .collect(Collectors.toList());
        config.setDefaultClientSupportedCipherSuites(filteredCipherSuites);
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

    public static void cleanupConfig(Config config) {
        boolean hasEcCipherSuite = false;
        for (CipherSuite suite : config.getDefaultClientSupportedCipherSuites()) {
            if (suite.name().toUpperCase().contains("_EC")) {
                hasEcCipherSuite = true;
            }
        }
        config.setAddEllipticCurveExtension(hasEcCipherSuite);
        config.setAddECPointFormatExtension(hasEcCipherSuite);
    }
}
