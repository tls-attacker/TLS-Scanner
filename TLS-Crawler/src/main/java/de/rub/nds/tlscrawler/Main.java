/*
 * TLS-Crawler - A TLS scanning tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlscrawler;

import de.rub.nds.crawler.CommonMain;
import de.rub.nds.crawler.config.ControllerCommandConfig;
import de.rub.nds.crawler.persistence.MongoPersistenceProvider;
import de.rub.nds.tlscrawler.config.TlsControllerCommandConfig;
import de.rub.nds.tlsscanner.serverscanner.report.ServerReport;

/** TLS-Crawler's main class. */
public class Main {

    public static void main(String[] args) {
        MongoPersistenceProvider.registerSerializer(ServerReport.getSerializers());
        ControllerCommandConfig controllerCommandConfig = new TlsControllerCommandConfig();
        CommonMain.main(args, controllerCommandConfig);
    }
}
