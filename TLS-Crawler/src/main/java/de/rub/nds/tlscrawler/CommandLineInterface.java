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
import de.rub.nds.tlscrawler.utility.AddressIteratorFactory;
import de.rub.nds.tlscrawler.utility.IAddressIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
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

        for (;;) {
            LOG.info("Starting command reception. Try \"help\" or \"newscan -h\".");
            String input = scanner.nextLine();

            LOG.debug(String.format("Received input: \"%s\"", input));

            String[] in_arr = input.split(Pattern.quote(" "));
            String[] args = in_arr.length <= 1 ? new String[] { } : Arrays.copyOfRange(in_arr, 1, in_arr.length);

            LOG.debug(Arrays.deepToString(in_arr));
            LOG.debug(Arrays.deepToString(args));

            switch (in_arr[0]) {
                case "newscan":
                    handleNewscan(master, args);

                break;

                case "exit": {
                    // TODO: Graceful teardown
                    LOG.info("Shutting down. Bye!");
                    System.exit(0);
                }

                break;

                case "help":
                default: {
                    System.out.println("Available options: 'newscan', 'help', 'exit'");
                    System.out.println("Try 'newscan -h'");
                }

                break;
            }
        }
    }

    private static void handleNewscan(TlsCrawlerMaster master, String[] args) {
        NewScanOptions options = NewScanOptions.parseOptions(args);

        if (options.help) {
            LOG.info(NewScanOptions.getHelpString());
            return;
        }

        List<String> chosenScans = options.scans;
        List<Integer> ports = options.ports.stream()
                .map(Integer::parseInt)
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

        master.crawl(chosenScans, targets, ports, options.id);
    }
}
