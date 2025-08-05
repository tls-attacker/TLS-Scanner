/*
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker
 *
 * Copyright 2017-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsscanner.serverscanner.test;

import de.rub.nds.scanner.core.config.ScannerDetail;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsscanner.serverscanner.config.ServerScannerConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;
import org.junit.jupiter.api.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public abstract class AbstractScannerIT extends AbstractDockerbasedIT {

    public AbstractScannerIT(
            TlsImplementationType implementation,
            String version,
            String additionalParameters,
            TransportType transportType) {
        super(implementation, version, additionalParameters, transportType);
    }

    public AbstractScannerIT(
            TlsImplementationType implementation, String version, String additionalParameters) {
        super(implementation, version, additionalParameters);
    }

    protected ServerReport runScanner(ServerScannerConfig config, boolean setHost) {
        if (setHost) {
            config.getClientDelegate().setHost(getServerAddress());
        }
        try (TlsServerScanner scanner = new TlsServerScanner(config)) {
            return scanner.scan();
        }
    }

    protected ServerReport runScanner(ServerScannerConfig config) {
        return runScanner(config, true);
    }

    protected ServerReport runScanner(ScannerDetail detail) {
        ServerScannerConfig config = new ServerScannerConfig(new GeneralDelegate());
        config.getExecutorConfig().setScanDetail(detail);
        config.getExecutorConfig().setOverallThreads(2);
        config.getExecutorConfig().setParallelProbes(2);
        return runScanner(config);
    }
}
