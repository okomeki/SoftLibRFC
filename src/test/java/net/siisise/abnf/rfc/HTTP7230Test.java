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
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class HTTP7230Test {
    
    public HTTP7230Test() {
    }

    @Test
    public void testSomeMethod() {
        assertTrue(HTTP7230.query.eq("slksje"));
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }
    
    /**
     * 最適化なしで突っ込む。
     * デバッグでは重いかも
     * @throws IOException 
     */
    @Test
    public void testResource() throws IOException {
//        ABNFReg http = new ABNFReg(getClass().getResource("HTTP7230.abnf"), URI3986.REG, HTTP7230.PAR);
//        assertTrue(http.href("query").eq("slksje"));
        // TODO review the generated test code and remove the default call to fail.
        //fail("The test case is a prototype.");
    }
}
