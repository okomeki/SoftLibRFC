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
 * RFC 2449 POP3 Extension 
 */
public class POP3Ex {
    public static final ABNFReg REG = new ABNFReg(ABNF5234.REG);
    
    // POP3 commands
    public static final ABNF param = REG.rule("param", ABNF5234.VCHAR.ix());
    public static final ABNF keyword = REG.rule("keyword", ABNF5234.VCHAR.x(3,4));
    public static final ABNF command = REG.rule("command", keyword.pl(ABNF5234.SP.pl(param).x().pl(ABNF5234.CRLF)));

    // POP3 responses
    public static final ABNF timestamp = REG.rule("timestamp", ABNF.bin('<').pl(ABNF5234.VCHAR.x(),ABNF.bin('>')));
    public static final ABNF schar = REG.rule("schar", ABNF.range(0x21,0x5a).or(ABNF.range(0x5c, 0x7f)));
    public static final ABNF status = REG.rule("status", ABNF.text("+OK").or(ABNF.text("-ERR")));
    public static final ABNF text = REG.rule("text", schar.x().or(REG.ref("resp-code")));
    public static final ABNF singleLine = REG.rule("single-line", status.pl(ABNF5234.SP.pl(text).c(),ABNF5234.CRLF));
    public static final ABNF rchar = REG.rule("rchar", ABNF.range(0x21,0x2e).or(ABNF.range(0x30,0x5c),ABNF.range(0x5e, 0x7f)));
    public static final ABNF respLevel = REG.rule("resp-level", rchar.ix());
    public static final ABNF respCode = REG.rule("resp-code", ABNF.bin('[').pl(respLevel, ABNF.bin('/').pl(respLevel).x(), ABNF.bin(']') ));
    public static final ABNF dotStuffed = REG.rule("dot-stuffed", ABNF5234.CHAR.x().pl(ABNF5234.CRLF));
    public static final ABNF multiLine = REG.rule("multi-line",singleLine.pl(dotStuffed.x(), ABNF.bin('.'), ABNF5234.CRLF));
    public static final ABNF greeting = REG.rule("greeting", ABNF.text("+OK"));
    public static final ABNF gchar = REG.rule("gchar", ABNF.range(0x21, 0x3b).or(ABNF.range(0x3d, 0x7f)));
    public static final ABNF cchar = REG.rule("cchar", ABNF.range(0x21, 0x2d).or(ABNF.range(0x2f, 0x7f)));
    public static final ABNF capaTag = REG.rule("capa-tag", cchar.ix());
    public static final ABNF capability = REG.rule("capability",capaTag.pl(ABNF5234.SP.pl(param).x(), ABNF5234.CRLF));
    public static final ABNF capaResp = REG.rule("capa-resp","single-line *capability \".\" CRLF");
    public static final ABNF response = REG.rule("response",greeting.or(singleLine, capaResp, multiLine));
}
