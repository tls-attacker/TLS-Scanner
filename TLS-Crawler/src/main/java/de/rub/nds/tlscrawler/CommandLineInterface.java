/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import de.rub.nds.tlscrawler.core.ITlsCrawlerSlave;
import de.rub.nds.tlscrawler.core.TlsCrawlerMaster;
import de.rub.nds.tlscrawler.data.IMasterStats;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Implements the command line interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class CommandLineInterface {
    private static Logger LOG = LoggerFactory.getLogger(CommandLineInterface.class);

    public static void handleInput(TlsCrawlerMaster master, ITlsCrawlerSlave slave) {
        LOG.trace("handleInput()");

        Scanner scanner = new Scanner(System.in);

        // TODO: Implement full CLI

        for (;;) {
            LOG.info("Starting command reception.");
            String input = scanner.next();

            LOG.debug(String.format("Received input: \"%s\"", input));

            switch (input) {
                case "test_scan":
                    List<String> chosenScans = new LinkedList<>();
                    chosenScans.add("test_scan");

                    List<String> targets = Arrays.asList("172.217.22.35");

                    List<Integer> ports = new ArrayList<>();
                    ports.add(32);
                    ports.add(34);
                    ports.add(89);
                    ports.add(254);
                    ports.add(754);
                    ports.add(8987);

                    master.crawl(chosenScans, targets, ports);
                    break;

                case "print":
                    IMasterStats stats = master.getStats();

                    LOG.info(String.format("Tasks completed: %d/%d", stats.getFinishedTasks(), stats.getTotalTasks()));
                    break;

                default:
                    System.out.println("Did not understand. Try again.");
            }
        }
    }
}
