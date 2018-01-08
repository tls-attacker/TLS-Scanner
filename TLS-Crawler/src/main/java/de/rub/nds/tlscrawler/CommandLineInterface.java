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
            LOG.info("Starting command reception. Try \"help\" or \"newscan -h\".");
            String input = scanner.next();

            LOG.debug(String.format("Received input: \"%s\"", input));

            String[] in_arr = input.split(" ");
            String[] args = in_arr.length <= 1 ? new String[] { } : Arrays.copyOfRange(in_arr, 1, in_arr.length);

            switch (in_arr[0]) {
                case "newscan": {
                    NewScanOptions options = NewScanOptions.parseOptions(args);

                    List<String> chosenScans = options.scans;
                    List<String> ip_whitelist = options.whitelist;
                    List<String> ip_blacklist = options.blacklist;
                    List<Integer> ports = options.ports;

                    List<String> targets = Arrays.asList("172.217.22.35");

                    master.crawl(chosenScans, targets, ports);
                }

                break;

                case "help": {
                    LOG.info("Available options: newscan, help, print, exit");
                }

                break;

                case "print": {
                    IMasterStats stats = master.getStats();
                    LOG.info(String.format("Tasks completed: %d/%d", stats.getFinishedTasks(), stats.getTotalTasks()));
                }

                break;

                case "exit": {
                    // TODO: Graceful teardown
                    LOG.info("Shutting down. Bye!");
                    System.exit(0);
                }

                break;

                default: {
                    System.out.println("Did not understand. Try again.");
                }

                break;
            }
        }
    }
}
