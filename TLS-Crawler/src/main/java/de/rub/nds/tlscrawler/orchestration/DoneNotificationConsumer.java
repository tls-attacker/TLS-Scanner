/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.orchestration;

import de.rub.nds.tlscrawler.data.ScanJob;

@FunctionalInterface
public interface DoneNotificationConsumer {

    void consumeDoneNotification(String consumerTag, ScanJob scanJob);
}