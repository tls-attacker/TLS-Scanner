package de.rub.nds.tlsscanner.clientscanner.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.CertificateDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;

public class ClientScannerConfig extends TLSDelegateConfig {

    @ParametersDelegate
    public GeneralDelegate generalDelegate;
    @ParametersDelegate
    public ServerDelegate serverDelegate;
    @ParametersDelegate
    private CACertDelegate certificateDelegate;

    @Parameter(names = "-timeout", required = false, description = "The timeout used for the scans in ms (default 1000)")
    private int timeout = 1000;

    @Parameter(names = "-file", required = false, description = "File to write the report to as xml")
    private String reportFile = null;

    public ClientScannerConfig(GeneralDelegate delegate) {
        super(delegate);
        this.generalDelegate = delegate;
        addDelegate(delegate);

        serverDelegate = new ServerDelegate();
        addDelegate(serverDelegate);

        this.certificateDelegate = new CACertDelegate();
        addDelegate(certificateDelegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig(Config.createConfig());
        config.getDefaultClientConnection().setTimeout(timeout);
        return config;
    }

    public String getReportFile() {
        return reportFile;
    }
}
