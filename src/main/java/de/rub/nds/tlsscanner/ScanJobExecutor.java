/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 * @author robert
 */
public abstract class ScanJobExecutor {

    public abstract SiteReport execute(ScannerConfig config, ScanJob scanJob);

    public abstract void shutdown();
}
