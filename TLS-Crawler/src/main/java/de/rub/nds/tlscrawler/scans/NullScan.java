/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler.scans;

import de.rub.nds.tlscrawler.data.IScan;
import de.rub.nds.tlscrawler.data.IScanTarget;
import de.rub.nds.tlscrawler.utility.Tuple;

import java.util.LinkedList;
import java.util.List;

import static java.util.stream.Collectors.joining;

/**
 * A null scan that only costs some (IO/processor) time.
 * Does not require network.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class NullScan implements IScan {
    private static String NAME = "null_scan";
    private static Integer WAIT_MS = 5000;

    @Override
    public String getName() {
        return NullScan.NAME;
    }

    @Override
    public List<Tuple> scan(IScanTarget target) {
        List<Tuple> result = new LinkedList<>();

        result.add(Tuple.create("target_ip", target.getIp()));
        result.add(Tuple.create("target_ports", target.getPorts().stream().map(x -> x.toString()).collect(joining(", "))));

        try {
            Thread.sleep(NullScan.WAIT_MS);
            result.add(Tuple.create("wait_time", NullScan.WAIT_MS.toString()));
        } catch (InterruptedException e) {
            result.add(Tuple.create("exception", e.toString()));
        }

        return result;
    }
}
