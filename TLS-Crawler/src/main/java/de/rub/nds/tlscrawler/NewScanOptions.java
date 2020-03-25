/**
 * TLS Crawler
 *
 * Licensed under Apache 2.0
 *
 * Copyright 2017 Ruhr-University Bochum
 */
package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

/**
 * Command Line Options for the interactive command line interface.
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class NewScanOptions extends OptionsBase {
    protected static Logger LOG = LoggerFactory.getLogger(NewScanOptions.class);

    protected static OptionsParser parser = OptionsParser.newOptionsParser(NewScanOptions.class);

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
            converter = Converters.CommaSeparatedOptionListConverter.class,
            defaultValue = ""
    )
    public List<String> scans;

    @Option(
            name = "ports",
            abbrev = 'p',
            help = "A list of ports.",
            allowMultiple = true,
            converter = Converters.CommaSeparatedOptionListConverter.class,
            defaultValue = ""
    )
    public List<String> ports;

    @Option(
            name = "targetsFromRedisList",
            abbrev = 'r',
            help = "Fetches targets from redis. Does not combine with blacklist switches.",
            defaultValue = ""
    )
    public String targetsFromRedisList;

    @Option(
            name = "whitelist",
            abbrev = 'w',
            help = "A list of IPs/CIDR-Blocks.",
            allowMultiple = true,
            converter = Converters.CommaSeparatedOptionListConverter.class,
            defaultValue = ""
    )
    public List<String> whitelist;

    @Option(
            name = "blacklist",
            abbrev = 'b',
            help = "A list of IPs/CIDR-Blocks.",
            allowMultiple = true,
            converter = Converters.CommaSeparatedOptionListConverter.class,
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

    @Option(
            name = "identifier",
            abbrev = 'i',
            help = "Scan tasks will be marked with this ID",
            defaultValue = ""
    )
    public String id;

    public boolean printWarning = false;

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
        NewScanOptions result = null;

        LOG.trace("parseOptions()");

        try {
            result = Options.parse(NewScanOptions.class, args).getOptions();
        } catch (OptionsParsingException e) {
            LOG.warn(e.getMessage());
            LOG.warn("Creating fallback options.");

            return getDefault();
        }

        if (result != null
                && result.ports.isEmpty()) {
            return getDefault();
        }

        if (result != null
                && result.scans.isEmpty()) {
            return getDefault();
        }

        if (result != null
                && !result.targetsFromRedisList.isEmpty()
                && !result.blacklist.isEmpty()) {
            return getDefault();
        }

        if (result != null
                && result.id.equals("")) {
            result.id = UUID.randomUUID().toString();
        }

        if (result != null
                && !result.targetsFromRedisList.isEmpty()
                && result.ndsBlacklist) {
            result.printWarning = true;
        }

        return result;
    }

    private static NewScanOptions getDefault() {
        NewScanOptions opts = new NewScanOptions();

        opts.ports = new LinkedList<>();
        opts.help = true;
        opts.targetsFromRedisList = "";
        opts.scans = new LinkedList<>();
        opts.blacklist = new LinkedList<>();
        opts.whitelist = new LinkedList<>();
        opts.ndsBlacklist = true;
        opts.id = UUID.randomUUID().toString();

        return opts;
    }
}
