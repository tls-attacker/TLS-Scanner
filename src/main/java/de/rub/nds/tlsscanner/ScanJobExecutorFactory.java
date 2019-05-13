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
