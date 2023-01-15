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
import net.siisise.abnf.parser5234.ABNF5234;

/**
 *
 */
public class OAuthBearer6750 {
    public static final ABNFReg REG = new ABNFReg(OAuth6749.REG);
    // Section 2.1. Authorization Request Header Field
    public static final ABNF b64token = REG.rule("b64token", ABNF5234.ALPHA.or1(ABNF5234.DIGIT,ABNF.bin("-._~+/")).ix().pl(ABNF.bin('=')));
    public static final ABNF credentials = REG.rule("Bearer", ABNF.text("Bearer").pl(ABNF5234.SP.ix(), b64token));

    
}
