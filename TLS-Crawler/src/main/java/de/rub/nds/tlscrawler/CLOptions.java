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

/**
 * Command Line Options class
 *
 * @author janis.fliegenschmidt@rub.de
 */
public class CLOptions extends OptionsBase {

    @Option(
            name = "help",
            abbrev = 'h',
            help = "Prints usage info.",
            defaultValue = "false"
    )
    public boolean help;

    @Option(
            name = "isMaster",
            abbrev = 'm',
            help = "Runs TLS-Crawler in Master or Slave mode.",
            defaultValue = "false"
    )
    public boolean isMaster;

    @Option(
            name = "instanceId",
            abbrev = 'i',
            help = "The ID of this TLS-Crawler instance.",
            defaultValue = ""
    )
    public String instanceId;

    @Option(
            name = "mongoDbConnectionString",
            abbrev = 'o',
            help = "Connection string of the MongoDB instance this crawler saves to.",
            defaultValue = ""
    )
    public String mongoDbConnectionString;

    @Option(
            name = "redisConnectionString",
            abbrev = 'r',
            help = "Connection string of the Redis instance this crawler uses to coordinate.",
            defaultValue = ""
    )
    public String redisConnectionString;
}
