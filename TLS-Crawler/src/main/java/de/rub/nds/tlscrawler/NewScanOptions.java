/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.Option;
import com.google.devtools.common.options.OptionsBase;
import com.google.devtools.common.options.OptionsParser;
import com.google.devtools.common.options.OptionsParsingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;

/**
 * Command Line Options for the interactive command line interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class NewScanOptions extends OptionsBase {
    private static Logger LOG = LoggerFactory.getLogger(NewScanOptions.class);

    private static OptionsParser parser = OptionsParser.newOptionsParser(NewScanOptions.class);

    @Option(
            name = "help",
            abbrev = 'h',
            help = "Prints the available commands and a description.",
            defaultValue = "false"
    )
    public boolean help;

    @Option(
            name = "scans",
            abbrev = 's',
            help = "A list of scans.",
            allowMultiple = true,
            defaultValue = ""
    )
    public List<String> scans;

    @Option(
            name = "ports",
            abbrev = 'p',
            help = "A list of ports.",
            allowMultiple = true,
            defaultValue = ""
    )
    public List<Integer> ports;

    @Option(
            name = "targetsFromRedisList",
            abbrev = 'r',
            help = "Defines a target source, e. g. Redis.",
            defaultValue = ""
    )
    public String targetsFromRedisList;

    @Option(
            name = "whitelist",
            abbrev = 'w',
            help = "A list of IPs/CIDR-Blocks.",
            allowMultiple = true,
            defaultValue = ""
    )
    public List<String> whitelist;

    @Option(
            name = "blacklist",
            abbrev = 'b',
            help = "A list of IPs/CIDR-Blocks.",
            allowMultiple = true,
            defaultValue = ""
    )
    public List<String> blacklist;

    @Option(
            name = "ndsBlacklist",
            abbrev = 'n',
            help = "Uses the NDS blacklist.",
            defaultValue = "true"
    )
    public boolean ndsBlacklist;

    public static String getHelpString() {
        return parser.describeOptions(Collections.<String, String>emptyMap(), OptionsParser.HelpVerbosity.LONG);
    }

    /**
     * Implements command line argument parsing.
     *
     * @param args The argument array.
     * @return An object containing sane arguments.
     * @throws OptionsParsingException
     */
    public static NewScanOptions parseOptions(String[] args) {
        NewScanOptions result;

        LOG.trace("parseOptions()");

        try {
            parser.parse(args);
        } catch (OptionsParsingException e) {
            LOG.warn(e.getMessage());
            LOG.warn("Creating fallback options.");

            try {
                parser.parse();
            } catch (OptionsParsingException e1) {
                // Can't happen
            }
        }

        result = parser.getOptions(NewScanOptions.class);

        // TODO sanity check

        return result;
    }
}
