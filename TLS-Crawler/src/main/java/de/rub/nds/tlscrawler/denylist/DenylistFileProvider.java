/**
 * TLS-Crawler - A tool to perform large scale scans with the TLS-Scanner
 *
 * Copyright 2018-2022 Paderborn University, Ruhr University Bochum
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlscrawler.denylist;

import de.rub.nds.tlscrawler.data.ScanTarget;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.InetAddressValidator;
import org.apache.commons.validator.routines.IntegerValidator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Reads the specified denylist file. Supports hostnames, ips and complete subnets as denylist entries.
 */
public class DenylistFileProvider implements IDenylistProvider {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Set<String> ipDenylistSet = new HashSet<>();
    private final List<SubnetUtils.SubnetInfo> cidrDenylist = new ArrayList<>();
    private final Set<String> domainDenylistSet = new HashSet<>();

    public DenylistFileProvider(String denylistFilename) {
        List<String> denylist = List.of();
        try (Stream<String> lines = Files.lines(Paths.get(denylistFilename))) {
            denylist = lines.collect(Collectors.toList());
        } catch (IOException e) {
            LOGGER.error("Could not read denylist {}", denylistFilename);
        }
        for (String denylistEntry : denylist) {
            if (DomainValidator.getInstance().isValid(denylistEntry)) {
                domainDenylistSet.add(denylistEntry);
            } else if (InetAddressValidator.getInstance().isValid(denylistEntry)) {
                ipDenylistSet.add(denylistEntry);
            } else if (denylistEntry.contains("/") && InetAddressValidator.getInstance().isValid(denylistEntry.split("/")[0])
                && IntegerValidator.getInstance().isValid(denylistEntry.split("/")[1])) {
                SubnetUtils utils = new SubnetUtils(denylistEntry);
                cidrDenylist.add(utils.getInfo());

            }
        }
    }

    @Override
    public synchronized boolean isDenylisted(ScanTarget target) {
        return domainDenylistSet.contains(target.getHostname()) || ipDenylistSet.contains(target.getIp())
            || cidrDenylist.stream().anyMatch(subnetInfo -> subnetInfo.isInRange(target.getIp()));
    }

}
