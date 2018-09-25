/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsscanner.config.ScannerConfig;

/**
 *
 * @author robert
 */
public class ScanJobExecutorFactory {

    public static ScanJobExecutor getScanJobExecutor(ScannerConfig config) {
        switch (config.getThreads()) {
            case 1:
                return new SingleThreadedScanJobExecutor();
            default:
                return new MultiThreadedScanJobExecutor(config.getThreads());
        }
    }
}
