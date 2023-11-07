/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler.config;

import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.crawler.config.ControllerCommandConfig;
import de.rub.nds.crawler.data.ScanConfig;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlscrawler.data.TlsScanConfig;
import de.rub.nds.tlsscanner.serverscanner.execution.TlsServerScanner;

public class TlsControllerCommandConfig extends ControllerCommandConfig {
    @ParametersDelegate private final StarttlsDelegate starttlsDelegate;

    public TlsControllerCommandConfig() {
        super();
        starttlsDelegate = new StarttlsDelegate();
    }

    @Override
    public ScanConfig getScanConfig() {
        return new TlsScanConfig(
                getScanDetail(),
                getReexecutions(),
                getScannerTimeout(),
                getStarttlsDelegate().getStarttlsType());
    }

    @Override
    public Class<?> getScannerClassForVersion() {
        return TlsServerScanner.class;
    }

    public StarttlsDelegate getStarttlsDelegate() {
        return starttlsDelegate;
    }
}
