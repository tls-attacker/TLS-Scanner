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
import de.rub.nds.tlscrawler.utility.AddressIteratorFactory;
import de.rub.nds.tlscrawler.utility.IAddressIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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
            String input = scanner.nextLine();

            LOG.debug(String.format("Received input: \"%s\"", input));

            String[] in_arr = input.split(Pattern.quote(" "));
            String[] args = in_arr.length <= 1 ? new String[] { } : Arrays.copyOfRange(in_arr, 1, in_arr.length);

            LOG.debug(Arrays.deepToString(in_arr));
            LOG.debug(Arrays.deepToString(args));

            switch (in_arr[0]) {
                case "newscan": {
                    if (args.length < 1)
                    {
                        args = new String[] { "-h" };
                    }

                    NewScanOptions options = NewScanOptions.parseOptions(args);

                    if (options.help) {
                        LOG.info(NewScanOptions.getHelpString());
                        break;
                    }

                    List<String> chosenScans = options.scans;
                    List<Integer> ports = options.ports.stream()
                            .map(x -> Integer.parseInt(x))
                            .collect(Collectors.toList());

                    AddressIteratorFactory addrFac = AddressIteratorFactory.getInstance();
                    IAddressIterator targets;
                    if (options.targetsFromRedisList.isEmpty()) {
                        List<String> ip_whitelist = options.whitelist;
                        List<String> ip_blacklist = options.blacklist;

                        addrFac.reset();
                        addrFac.applyDefaultConfig(AddressIteratorFactory.Configurations.NDS_BLACKLIST);
                        addrFac.addToWhitelist(ip_whitelist);
                        addrFac.addToBlacklist(ip_blacklist);
                        targets = addrFac.build();
                    } else {
                        targets = AddressIteratorFactory.getRedisAddressSource(options.targetsFromRedisList);
                    }

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
