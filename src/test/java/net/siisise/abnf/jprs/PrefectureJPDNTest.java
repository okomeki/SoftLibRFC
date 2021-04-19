package net.siisise.abnf.jprs;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class PrefectureJPDNTest {
    
    public PrefectureJPDNTest() {
    }

    @Test
    public void testSomeMethod() {
        assertTrue(PrefectureJPDN.prefectureJPDN.is("さ.OSAka.jp"));
        assertTrue(PrefectureJPDN.prefectureJPDN.is("梅.和歌山.jp"));
    }
    
}
