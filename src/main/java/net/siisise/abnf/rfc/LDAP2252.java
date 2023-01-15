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
 * LDAP v3
 */
public class LDAP2252 {
    static final ABNFReg REG = new ABNFReg();
    
    static final ABNF a = REG.rule("a", ABNF.range('a', 'z').or1(ABNF.range('A','Z')));
    static final ABNF d = REG.rule("d", ABNF.range('0','9'));
    static final ABNF hexDigit = REG.rule("hex-digit",d.or1(ABNF.range('a','f'),ABNF.range('A','F')));
    static final ABNF k = REG.rule("k", a.or1(d,ABNF.bin("-;")));
    static final ABNF p = REG.rule("p", a.or1(d,ABNF.bin("\"()+,-./:? ")));
    static final ABNF letterstring = REG.rule("letterstring", a.ix());
    static final ABNF numericstring = REG.rule("numericstring", d.ix());
    static final ABNF anhstring = REG.rule("anhstring",k.ix());
    static final ABNF keystring = REG.rule("keystring", a.pl(anhstring.c()));
    static final ABNF printablestring = REG.rule("printablestring", p.ix());
    static final ABNF space = REG.rule("space", ABNF.bin(0x20).ix());
    static final ABNF whsp = REG.rule("whsp", space.c());
    static final ABNF utf8 = REG.rule("utf8", ABNF.range(0x00,0x10ffff));
    static final ABNF dstring = REG.rule("dstring", utf8.ix());
    static final ABNF qdstring = REG.rule("qdstring", whsp.pl(ABNF.bin('\''),dstring,ABNF.bin('\''),whsp));
    static final ABNF qdstringlist = REG.rule("qdstringlist",qdstring.x());
    static final ABNF qdstrings = REG.rule("qdstrings", qdstring.or(whsp.pl(ABNF.bin('('),qdstringlist,ABNF.bin(')'),whsp)));
    public static final ABNF descr = REG.rule("descr", keystring);
    
    static final ABNF numericoid = REG.rule("numericoid", numericstring.pl(ABNF.bin('.').pl(numericstring).x()));
    public static final ABNF oid = REG.rule("oid", descr.or(numericoid));
    static final ABNF woid = REG.rule("woid", whsp.pl(oid,whsp));
}
