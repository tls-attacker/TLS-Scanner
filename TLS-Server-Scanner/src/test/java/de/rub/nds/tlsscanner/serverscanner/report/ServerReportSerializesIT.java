/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.report;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsscanner.core.constants.TlsProbeType;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.test.AbstractScannerIT;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag(TestCategories.INTEGRATION_TEST)
class ServerReportSerializesIT extends AbstractScannerIT {
    public ServerReportSerializesIT() {
        super(TlsImplementationType.OPENSSL, "1.1.1f", "");
    }

    @Test
    void realReportSerializes() {
        ServerScannerConfig cfg = new ServerScannerConfig(new GeneralDelegate());
        cfg.getExecutorConfig().setScanDetail(ScannerDetail.QUICK);
        cfg.setTimeout(100);
        ServerReport report = runScanner(cfg);
        ServerReportSerializesTest.serializeCheckingFailingProperties(report);
    }

    @Test
    void certificateReportSerializes() {
        ServerScannerConfig cfg = new ServerScannerConfig(new GeneralDelegate());
        cfg.getExecutorConfig()
                .setProbes(
                        TlsProbeType.CIPHER_SUITE,
                        TlsProbeType.PROTOCOL_VERSION,
                        TlsProbeType.CERTIFICATE);
        ServerReport report = runScanner(cfg);
        ServerReportSerializesTest.serializeCheckingFailingProperties(report);
    }
}
