/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlscrawler.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlscrawler.config.delegate.RedisDelegate;
import lombok.Getter;
import lombok.Setter;

/**
 * @author robert
 */
@Getter
@Setter
public class ControllerCommandConfig {

    @ParametersDelegate
    private final RedisDelegate redisDelegate;
    @ParametersDelegate
    private final StarttlsDelegate starttlsDelegate;
    @Parameter(names = "-portToBeScanned", description = "The port that should be scanned.")
    private int port = 443;
    @Parameter(names = "-timeout", description = "The timeout to use inside the TLS-Scanner.")
    private int scannerTimeout = 2000;
    @Parameter(names = "-reexecutions", description = "Number of reexecutions to use in the TLS-Scanner.")
    private int reexecutions = 3;
    @Parameter(names = "-scansToBeExecuted", description = "The number of scans that should be executed. 0 = indefinetly")
    private int scansToBeExecuted = 1;
    @Parameter(names = "-waitAfterScan", description = "The number of minutes to wait after a scan has completed. 0 = back to back")
    private int waitTimeAfterScan = 0;
    @Parameter(names = "-scanName", description = "The name of the scan")
    private String scanName;
    @Parameter(names = "-hostFile", description = "A file of a list of servers which should be scanned.")
    private String hostFile;

    public ControllerCommandConfig() {
        redisDelegate = new RedisDelegate();
        starttlsDelegate = new StarttlsDelegate();
    }

}
