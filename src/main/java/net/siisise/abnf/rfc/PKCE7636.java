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

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;

/**
 * RFC 7636 Proof Key for Code Exchange by OAuth Public Clients
 */
public class PKCE7636 {
    public static final ABNFReg REG = new ABNFReg();

    // 4.1. Client Creates a Code Verifier
    static final ABNF ALPHA = REG.rule("ALPHA",ABNF.range(0x41, 0x5a).or1(ABNF.range(0x61,0x7a)));
    static final ABNF DIGIT = REG.rule("DIGIT", ABNF.range(0x30, 0x39));
    static final ABNF unreserved = REG.rule("unreserved", ALPHA.or1(DIGIT,ABNF.bin("-._~")));
    public static final ABNF codeVerifier = REG.rule("code-verifier", unreserved.x(43,128));
    
    // 4.2. Client Creates the Code Challenge
    public static final ABNF codeChallenge = REG.rule("code-challenge", unreserved.x(43,128));
}
