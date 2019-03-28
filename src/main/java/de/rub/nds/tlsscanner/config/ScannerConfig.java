/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsscanner.constants.ScannerDetail;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScannerConfig extends TLSDelegateConfig {

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @Parameter(names = "-threads", required = false, description = "How many threads should execute Probes")
    private int threads = 1;

    @Parameter(names = "-danger", required = false, description = "Integer value (1 - 10) which specifies how aggressive the Scanner should test. Default 10")
    private int dangerLevel = 10;

    @Parameter(names = "-noColor", required = false, description = "If you use Windows or don't want colored text.")
    private Boolean noColor = false;

    @ParametersDelegate
    private GeneralDelegate generalDelegate;

    @Parameter(names = "-implementation", required = false, description = "If you are interessted in the vulnerability of an implementation rather than a specific site")
    private boolean implementation = false;

    @Parameter(names = "-scanDetail", required = false, description = "How detailed do you want to scan?")
    private ScannerDetail scanDetail = ScannerDetail.NORMAL;

    @Parameter(names = "-reportDetail", required = false, description = "How detailed do you want the report to be?")
    private ScannerDetail reportDetail = ScannerDetail.NORMAL;

    @Parameter(names = "-aggressiv", required = false, description = "The level of concurrent handshakes (only applies to some resource intensive tests)")
    private int aggroLevel = 1;

    @Parameter(names = "-timeout", required = false, description = "The timeout used for the scans in ms (default 1000)")
    private int timeout = 1000;

    private boolean noProgressbar = false;

    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    public ScannerConfig(GeneralDelegate delegate) {
        super(delegate);
        this.generalDelegate = delegate;
        clientDelegate = new ClientDelegate();
        starttlsDelegate = new StarttlsDelegate();
        addDelegate(clientDelegate);
        addDelegate(generalDelegate);
        addDelegate(starttlsDelegate);
    }

    public boolean isNoProgressbar() {
        return noProgressbar;
    }

    public void setNoProgressbar(boolean noProgressbar) {
        this.noProgressbar = noProgressbar;
    }

    public int getAggroLevel() {
        return aggroLevel;
    }

    public void setAggroLevel(int aggroLevel) {
        this.aggroLevel = aggroLevel;
    }

    public int getThreads() {
        return threads;
    }

    public void setThreads(int threads) {
        this.threads = threads;
    }

    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }

    public StarttlsDelegate getStarttlsDelegate() {
        return starttlsDelegate;
    }

    public int getDangerLevel() {
        return dangerLevel;
    }

    public void setDangerLevel(int dangerLevel) {
        this.dangerLevel = dangerLevel;
    }

    public boolean isImplementation() {
        return implementation;
    }

    public void setImplementation(boolean implementation) {
        this.implementation = implementation;
    }

    public Boolean isNoColor() {
        return noColor;
    }

    public void setNoColor(boolean noColor) {
        this.noColor = noColor;
    }

    public ScannerDetail getScanDetail() {
        return scanDetail;
    }

    public void setScanDetail(ScannerDetail scanDetail) {
        this.scanDetail = scanDetail;
    }

    public ScannerDetail getReportDetail() {
        return reportDetail;
    }

    public void setReportDetail(ScannerDetail reportDetail) {
        this.reportDetail = reportDetail;
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig(Config.createConfig());
        config.setSniHostname(clientDelegate.getHost());
        config.getDefaultClientConnection().setTimeout(timeout);
        return config;
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }
}
