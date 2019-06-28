/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsscanner.config.ScannerConfig;

public class ScanJobExecutorFactory {

    public static ScanJobExecutor getScanJobExecutor(ScannerConfig config) {
        switch (config.getParallelProbes()) {
            case 1:
                return new SingleThreadedScanJobExecutor();
            default:
                return new MultiThreadedScanJobExecutor(config.getParallelProbes(), config.getClientDelegate().getHost());
        }
    }
}
