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
 * RFC 2616 Hypertext Transfer Protocol -- HTTP/1.1.
 * RFC 7230により廃止 適度にABNF風にしたもの
 * @deprecated RFC 7230
 */
public class HTTP2616 {

    public static final ABNFReg REG = new ABNFReg();

    static final ABNF OCTET = REG.rule("OCTET", ABNF.binRange(0x00, 0xff));
    static final ABNF CHAR = REG.rule("CHAR", ABNF.binRange(0x00, 0x7f));
    static final ABNF UPALPHA = REG.rule("UPALPHA", ABNF.range('A', 'Z'));
    static final ABNF LOALPHA = REG.rule("LOALPHA", ABNF.range('a', 'z'));
    static final ABNF ALPHA = REG.rule("ALPHA", UPALPHA.or1(LOALPHA));
    static final ABNF DIGIT = REG.rule("DIGIT", ABNF.range('0', '9'));
    static final ABNF CTL = REG.rule("CTL", ABNF.binRange(0x0, 0x1f).or1(ABNF.bin(0x7f)));
    static final ABNF CR = REG.rule("CR", ABNF.bin(0x0d));
    static final ABNF LF = REG.rule("LF", ABNF.bin(0x0a));
    static final ABNF SP = REG.rule("SP", ABNF.bin(0x20));
    static final ABNF HT = REG.rule("HT", ABNF.bin(0x09));
    static final ABNF doubleQuote = REG.rule("double-quote", ABNF.bin(0x22));

    static final ABNF CRLF = REG.rule("CRLF", CR.pl(LF));
    static final ABNF LWS = REG.rule("LWS", CRLF.c().pl(SP.or1(HT).ix()));

    static final ABNF TEXT = REG.rule("TEXT", OCTET.mn(CTL).or(LWS));
    static final ABNF HEX = REG.rule("HEX", ABNF.range('A', 'F').or1(ABNF.range('a', 'f'), DIGIT));

    static final ABNF separators = REG.rule("separators", ABNF.bin("()<>@,;:\\\"/[]?={}").or1(SP, HT));
    public static final ABNF token = CHAR.mn(CTL).mn(separators);

    static final ABNF qdtext = REG.rule("qdtext", TEXT.mn(ABNF.bin('"')));
    static final ABNF quotedPair = REG.rule("quoted-pair", ABNF.bin('\\').pl(CHAR));
    public static final ABNF quotedString = REG.rule("quoted-string", ABNF.bin('"').pl(qdtext.or1(quotedPair).x(), ABNF.bin('"')));
}
