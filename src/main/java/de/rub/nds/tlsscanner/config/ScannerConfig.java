/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
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
import org.bouncycastle.util.IPAddress;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ScannerConfig extends TLSDelegateConfig {

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @Parameter(names = "-parallelProbes", required = false, description = "Defines the number of threads responsible for different TLS probes. If set to 1, only one specific TLS probe (e.g., TLS version scan) can be run in time.")
    private int parallelProbes = 1;

    @Parameter(names = "-danger", required = false, description = "Integer value (1 - 10) which specifies how aggressive the Scanner should test. Default 10")
    private int dangerLevel = 10;

    @Parameter(names = "-noColor", required = false, description = "If you use Windows or don't want colored text.")
    private boolean noColor = false;

    @ParametersDelegate
    private GeneralDelegate generalDelegate;

    @Parameter(names = "-scanDetail", required = false, description = "How detailed do you want to scan?")
    private ScannerDetail scanDetail = ScannerDetail.NORMAL;

    @Parameter(names = "-reportDetail", required = false, description = "How detailed do you want the report to be?")
    private ScannerDetail reportDetail = ScannerDetail.NORMAL;

    @Parameter(names = "-overallThreads", required = false, description = "The maximum number of threads used to execute TLS probes located in the scanning queue. This is also the maximum number of threads communicating with the analyzed server.")
    private int overallThreads = 1;

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

    public ScannerConfig(GeneralDelegate delegate, ClientDelegate clientDelegate) {
        super(delegate);
        this.generalDelegate = delegate;
        this.clientDelegate = clientDelegate;
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

    public int getOverallThreads() {
        return overallThreads;
    }

    public void setOverallThreads(int overallThreads) {
        this.overallThreads = overallThreads;
    }

    public int getParallelProbes() {
        return parallelProbes;
    }

    public void setParallelProbes(int parallelProbes) {
        this.parallelProbes = parallelProbes;
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

    public boolean isNoColor() {
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
        if (!IPAddress.isValid(config.getDefaultClientConnection().getHostname()) || clientDelegate.getSniHostname() != null) {
            config.setAddServerNameIndicationExtension(true);
        } else {
            config.setAddServerNameIndicationExtension(false);
        }

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
