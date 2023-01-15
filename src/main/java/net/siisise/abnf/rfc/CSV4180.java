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
 * RFC 4180
 * update 7111
 */
public class CSV4180 {

    public static final ABNFReg REG = new ABNFReg();
    
    static ABNF LF = REG.rule("LF", ABNF5234.LF);
    static ABNF CR = REG.rule("CR", ABNF5234.CR);
    static ABNF CRLF = REG.rule("CRLF", ABNF5234.CRLF);
    public static ABNF DQUOTE = REG.rule("DQUOTE", ABNF.bin(0x22));
    public static ABNF COMMA = REG.rule("COMMA", ABNF.bin(0x2c));
    public static ABNF TEXTDATA = REG.rule("TEXTDATA", "%x20-21 / %x23-2B / %x2D-7e");
    public static ABNF nonEscaped = REG.rule("non-escaped",TEXTDATA.x());
    public static ABNF escaped = REG.rule("escaped", "DQUOTE *(TEXTDATA / COMMA / CR / LF / 2DQUOTE) DQUOTE");
    public static ABNF field = REG.rule("field", escaped.or(nonEscaped));
    public static ABNF name = REG.rule("name", field);
    public static ABNF record = REG.rule("record", "field *(COMMA field)");
    public static ABNF header = REG.rule("header", "name *(COMMA name)");
    public static ABNF file = REG.rule("[header CRLF] record *(CRLF record) [CRLF]");
}
