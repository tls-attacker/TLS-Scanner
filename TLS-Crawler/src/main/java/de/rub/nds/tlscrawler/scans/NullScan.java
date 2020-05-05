/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.ScanTarget;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bson.Document;

/**
 * A null scan that only costs some (IO/processor) time. Does not require
 * network.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class NullScan implements IScan {

    private static Logger LOG = LogManager.getLogger();

    private static String NAME = "null_scan";
    private static Integer WAIT_MS = 5000;

    // TODO This scan should also use the fully qualified class name. TBI with aliases.
    @Override
    public String getName() {
        return NullScan.NAME;
    }

    @Override
    public Document scan(ScanTarget target) {
        LOG.trace("scan()");

        Document document = new Document();
        LOG.info("testing: " + target.getIp());
        document.put("target_ip", target.getIp());
        document.put("target_ports", target.getPort());
        try {
            LOG.trace("Going to sleep.");
            Thread.sleep(NullScan.WAIT_MS);
            document.put("wait_time", NullScan.WAIT_MS);
        } catch (InterruptedException e) {
            document.put("exception", e.toString());
        }

        return document;
    }
}
