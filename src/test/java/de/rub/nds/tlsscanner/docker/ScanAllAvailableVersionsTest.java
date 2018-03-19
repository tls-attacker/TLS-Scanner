/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.docker;

import de.rub.nds.tls.subject.TlsServer;
import de.rub.nds.tls.subject.docker.DockerSpotifyTlsServerManager;
import de.rub.nds.tls.subject.docker.DockerTlsServerManagerFactory;
import de.rub.nds.tls.subject.docker.DockerTlsServerType;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.util.UnlimitedStrengthEnabler;
import de.rub.nds.tlsattacker.util.tests.DockerTests;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(DockerTests.class)
public class ScanAllAvailableVersionsTest {
    
    private DockerSpotifyTlsServerManager serverManager;
    private TlsServer server = null;
    
    public ScanAllAvailableVersionsTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
        UnlimitedStrengthEnabler.enable();
        Security.addProvider(new BouncyCastleProvider());
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
        if (server != null) {
            server.kill();
        }
    }
    
    @Test
    public void scanAll() {
        for (DockerTlsServerType type : DockerTlsServerType.values()) {
            for (String version : DockerTlsServerManagerFactory.getAvailableVersions(type)) {
                System.out.println("Scanning: " +type + ":" + version);
                serverManager = DockerTlsServerManagerFactory.get(type, version);
                try {
                    server = serverManager.getTlsServer();
                    ScannerConfig scannerConfig = new ScannerConfig(new GeneralDelegate());
                    scannerConfig.getClientDelegate().setHost(server.host + ":" + server.port);
                    scannerConfig.setDangerLevel(10);
                    TlsScanner scanner = new TlsScanner(scannerConfig);
                    SiteReport siteReport = scanner.scan();
                    System.out.println(siteReport.toString());
                } catch (Exception E) {
                    E.printStackTrace();
                } finally {
                    if (server != null) {
                        server.kill();
                    }
                }
            }
        }
    }
}
