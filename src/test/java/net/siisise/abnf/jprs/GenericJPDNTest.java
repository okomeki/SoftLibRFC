package net.siisise.abnf.jprs;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class GenericJPDNTest {
    
    public GenericJPDNTest() {
    }
    
    @Test
    public void testAnum() {
        //ABNFReg reg = new ABNFReg(ABNF5234.BASE);
        assertTrue(GenericJPDN.ALNUM.x().eq("abc"));
    }
    
    @Test
    public void testAbnfFile() throws IOException {
        System.out.println("ABNF fileのテスト");
        ABNFReg reg = new ABNFReg();
        
        URL jpdnurl = getClass().getResource("GenericJPDN.abnf");
        List<ABNF> ab = reg.rulelist(jpdnurl);
        System.out.println(ab.size());
        ABNF gen = reg.ref("generic-JPDN");
        assertTrue(gen.eq("汎用jpドメイン.jp"));
    }

    @Test
    public void testJAlabel() {
        System.out.println("へ" + GenericJPDN.ALNUM.getClass().getName());
        System.out.println(GenericJPDN.ALNUM.toString());
        assertTrue(GenericJPDN.ALNUM.eq("a"));
        assertTrue(GenericJPDN.ALNUM_HYPHEN.eq("a"));
        assertTrue(GenericJPDN.JA_char.eq("め"));
        assertTrue(GenericJPDN.JA_char.eq("姫"));
        assertTrue(GenericJPDN.JA_char.eq("粉"));
        System.out.println("JA-char OK");
        
        System.out.println(GenericJPDN.JAlabel.toString());
//        System.out.println("JA-label1a");
//        assertTrue(GenericJPDN.JAlabel1a.eq("めだ"));
//        System.out.println("JA-label1b");
//        assertFalse(GenericJPDN.JAlabel1b.eq("めだ"));
//        System.out.println("JA-label1c");
//        assertTrue(GenericJPDN.JAlabel1c.eq("めだ"));
//        System.out.println("JA-label1");
//        assertTrue(GenericJPDN.JAlabel1.eq("めだ"));
//        System.out.println("JA-label2");
//        assertFalse(GenericJPDN.JAlabel2.eq("めだ"));
        System.out.println("JA-label");
        assertTrue(GenericJPDN.JAlabel.eq("めだ"));
        System.out.println("JA-label OK");
    }

    @Test
    public void testGenericJPDN() {
        assertTrue(GenericJPDN.label.eq("むら"));
        System.out.println("label OK");
        assertTrue(ABNF.text(".JP").eq(".JP"));
        System.out.println(".JP OK");
        assertTrue(GenericJPDN.label.pl(ABNF.text(".JP")).eq("むむ.JP"));
        System.out.println("label .JP OK");
        assertTrue(GenericJPDN.genericJPDN.eq("汎用.JP"));
        System.out.println("OK4");
    }
    
}
