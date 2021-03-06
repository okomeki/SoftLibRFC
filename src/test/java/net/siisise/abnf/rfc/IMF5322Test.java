package net.siisise.abnf.rfc;

import java.io.IOException;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class IMF5322Test {
    
    public IMF5322Test() {
    }

    @Test
    public void testSomeMethod() {
        assertTrue(IMF5322.addrSpec.eq("okome@example.com"));
//        assertTrue(IMF5322.addrSpec.eq("okome@example.com"));
//        fail("The test case is a prototype.");
    }
    
    @Test
    public void testTextFormat() throws IOException {
        ABNFReg REG = new ABNFReg(getClass().getResource("IMF5322.abnf"), ABNF5234.BASE);
         
        assertTrue(REG.ref("addr-spec").eq("okome@example.com"));
//        assertTrue(IMF5322.addrSpec.eq("okome@example.com"));
//        fail("The test case is a prototype.");
    }
}
