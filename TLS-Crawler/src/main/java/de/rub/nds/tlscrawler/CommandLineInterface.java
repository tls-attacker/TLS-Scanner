/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import de.rub.nds.tlscrawler.core.ITlsCrawlerSlave;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Scanner;
import java.util.regex.Pattern;

/**
 * Implements the command line interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class CommandLineInterface {
    private static Logger LOG = LoggerFactory.getLogger(CommandLineInterface.class);

    public static void handleInput() {
        LOG.trace("handleInput()");

        Scanner scanner = new Scanner(System.in);

        for (;;) {
            LOG.info("Starting command reception. Try \"help\" or \"exit\".");
            String input = scanner.nextLine();

            LOG.debug("Received input: {}", input);

            String[] in_arr = input.split(Pattern.quote(" "));
            String[] args = in_arr.length <= 1 ? new String[] { } : Arrays.copyOfRange(in_arr, 1, in_arr.length);

            LOG.debug(Arrays.deepToString(in_arr));
            LOG.debug(Arrays.deepToString(args));

            switch (in_arr[0]) {

                case "exit": {
                    // TODO: Graceful teardown
                    LOG.info("Shutting down. Bye!");
                    System.exit(0);
                }

                break;

                case "help":
                default: {
                    System.out.println("Available options: 'help', 'exit'");
                    System.out.println("Try 'newscan -h'");
                }

                break;
            }
        }
    }
}
