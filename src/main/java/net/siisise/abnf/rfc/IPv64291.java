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
 *
 */
public class IPv64291 {
    public static final ABNFReg REG = new ABNFReg();    
//    static ABNF ipv6Network = REG.rule("ipv6-network", IPv62373.IPv6address);
    // Section 2.2.
    static ABNF IPv6address = REG.rule("ipv6-address", URI3986.IPv6address);
}
