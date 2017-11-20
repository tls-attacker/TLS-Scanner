/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.IScanResult;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.data.ScanResult;

import java.util.stream.Collectors;

/**
 * A null scan that only costs some (IO/processor) time.
 * Does not require network.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class NullScan implements IScan {
    private static String NAME = "null_scan";
    private static Integer WAIT_MS = 5000;

    // TODO This scan should also use the fully qualified class name. TBI with aliases.

    @Override
    public String getName() {
        return NullScan.NAME;
    }

    @Override
    public IScanResult scan(IScanTarget target) {
        IScanResult result = new ScanResult();

        result.addString("target_ip", target.getIp());
        result.addString("target_ports", target.getPorts().stream()
                .map(x -> x.toString())
                .collect(Collectors.joining(", ")));

        try {
            Thread.sleep(NullScan.WAIT_MS);
            result.addInteger("wait_time", NullScan.WAIT_MS);
        } catch (InterruptedException e) {
            result.addString("exception", e.toString());
        }

        return result;
    }
}
