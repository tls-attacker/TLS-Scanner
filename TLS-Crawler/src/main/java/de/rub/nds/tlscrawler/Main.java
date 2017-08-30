/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.OptionsParser;

import java.util.Collections;
import java.util.UUID;

/**
 * TLS-Crawler's main class.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class Main {
    private static String usageInfo;

    public static void main(String[] args) {
        CLOptions options = parseOptions(args);

        if (options.help) {
            System.out.println(usageInfo);
            System.exit(0);
        }

        // Try MongoDB Connection

        // Try Redis Connection

        // Set up crawler

        System.out.println("TLS-Crawler is running as a " + (options.isMaster ? "master" : "slave") + " node with id "
                + options.instanceId + ".");
    }

    static CLOptions parseOptions(String[] args) {
        CLOptions result;

        OptionsParser parser = OptionsParser.newOptionsParser(CLOptions.class);
        parser.parseAndExitUponError(args);
        result = parser.getOptions(CLOptions.class);

        usageInfo = parser.describeOptions(Collections.<String, String>emptyMap(), OptionsParser.HelpVerbosity.LONG);

        if (result.instanceId.equals("")) {
            result.instanceId = UUID.randomUUID().toString();
        }

        return result;
    }
}
