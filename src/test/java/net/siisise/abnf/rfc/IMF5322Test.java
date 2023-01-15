/*
 * Copyright 2022 okome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
