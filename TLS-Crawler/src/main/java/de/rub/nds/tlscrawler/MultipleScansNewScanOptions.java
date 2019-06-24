package de.rub.nds.tlscrawler;

import com.google.devtools.common.options.Option;
import com.google.devtools.common.options.Options;
import com.google.devtools.common.options.OptionsParsingException;

import java.util.LinkedList;
import java.util.UUID;

public class MultipleScansNewScanOptions extends NewScanOptions {
    @Option(
            name = "numberOfScans",
            abbrev = 'q',
            help = "Prints the available commands and a description.",
            defaultValue = "inf"
    )

    public String numberOfScans;

    public static MultipleScansNewScanOptions parseOptions(String[] args) {
        MultipleScansNewScanOptions result = null;

        LOG.trace("parseOptions()");

        try {
            result = Options.parse(MultipleScansNewScanOptions.class, args).getOptions();
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

        if (result != null
                && result.numberOfScans.equals("")) {
            result.numberOfScans = "env";
        }

        return result;
    }



    private static MultipleScansNewScanOptions getDefault() {
        MultipleScansNewScanOptions opts = new MultipleScansNewScanOptions();

        opts.ports = new LinkedList<>();
        opts.help = true;
        opts.targetsFromRedisList = "";
        opts.scans = new LinkedList<>();
        opts.blacklist = new LinkedList<>();
        opts.whitelist = new LinkedList<>();
        opts.ndsBlacklist = true;
        opts.id = UUID.randomUUID().toString();
        opts.numberOfScans = "env";

        return opts;
    }








}


