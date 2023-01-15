/*
 * Copyright 2023 okome.
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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import net.siisise.bnf.BNF;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 * @author okome
 */
public class HTTP9112Test {
    
    public HTTP9112Test() {
    }

    @Test
    public void testSomeMethod() {
        System.out.println("HTTP9112");
        Packet pac = new PacketA();
        Charset utf8 = StandardCharsets.UTF_8;
        String buffer = "Host: 127.2.3.4:1234\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0\r\n\r\n";
        pac.write(buffer.getBytes(utf8));
        BNF.Match result = HTTP9112.REG.find(pac, "trailer-section", "field-line");
        System.out.println("size : " + result.sub.size());
        System.out.println(new String(result.sub.toByteArray(),utf8));
        // TODO review the generated test code and remove the default call to fail.
        assertNotNull(result);
    }
    
}
