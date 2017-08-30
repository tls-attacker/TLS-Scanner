package de.rub.nds.tlscrawler;

import org.junit.Test;

import static org.junit.Assert.*;

public class MainTest {

    @Test
    public void CLIParsingSmokeTest() {
        String[] options = {
                "-m",
                "-i", "myinstance",
                "-o", "mymongo",
                "-r", "myredis"
        };

        CLOptions parsed = Main.parseOptions(options);

        assertNotNull(parsed);

        assertEquals(true, parsed.isMaster);
        assertEquals("myinstance", parsed.instanceId);
        assertEquals("mymongo", parsed.mongoDbConnectionString);
        assertEquals("myredis", parsed.redisConnectionString);
    }
}