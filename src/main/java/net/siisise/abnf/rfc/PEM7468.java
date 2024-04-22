/*
 * Copyright 2024 okome.
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
 * RFC 7468 PKIX, PKCS, CMS のPEM
 */
public class PEM7468 {
    public static final ABNFReg REG = new ABNFReg(ABNF5234.BASE);

    static final ABNF labelchar = REG.rule("labelchar", ABNF.range(0x21,0x2c).or1(ABNF.range(0x2e,0x7e)));
    static final ABNF label = REG.rule("label", labelchar.pl(ABNF.bin('-').or1(ABNF5234.SP).c().pl(labelchar).x()).c());
    static final ABNF preeb = REG.rule("preeb", ABNF.text("-----BEGIN ").pl(label,ABNF.text("-----")));
    static final ABNF posteb = REG.rule("posteb", ABNF.text("-----END ").pl(label, ABNF.text("-----")));
    static final ABNF base64char = REG.rule("base64char", ABNF5234.ALPHA.or1(ABNF5234.DIGIT, ABNF.binlist("+/")));
    static final ABNF base64pad = REG.rule("base64pad",ABNF.bin('='));
    static final ABNF eol = REG.rule("eol", ABNF5234.CRLF.or(ABNF5234.CR,ABNF5234.LF));
    static final ABNF eolWSP = REG.rule("eolWSP", ABNF5234.WSP.or(ABNF5234.CR, ABNF5234.LF));
    static final ABNF base64line = REG.rule("base64line", base64char.ix().pl( ABNF5234.WSP.x(), eol));
    static final ABNF base64finl = REG.rule("base64finl", base64char.x().pl(base64pad.pl(ABNF5234.WSP.x(),eol,base64pad).or(
            base64pad.x(0,2)),ABNF5234.WSP.x(),eol));

    static final ABNF base64text = REG.rule("base64text", base64line.x().pl(base64finl));
    // ABNF (標準 Standard)
    public static final ABNF textualmsg = REG.rule("textualmsg", preeb.pl(ABNF5234.WSP.x(),eol,eolWSP.x(),base64text,posteb,ABNF5234.WSP.x(),eol.c()));

    static final ABNF W = REG.rule("W", ABNF5234.WSP.or(ABNF5234.CR,ABNF5234.LF,ABNF.bin(0x0b),ABNF.bin(0x0c)));
    static final ABNF laxbase64text = REG.rule("laxbase64text", W.or(base64char).x().pl(base64pad.pl(W.x(),base64pad.pl(W.x()).c()).c()));
    // ABNF (緩い Lax)
    public static final ABNF laxtextualmsg = REG.rule("laxtextualmsg", W.x().pl(preeb,laxbase64text,posteb, W.x()));
    
    static final ABNF strictbase64finl = REG.rule("strictbase64finl", base64char.x(4).x(0,15).pl(base64char.x(4).or1(base64char.x(3).pl(base64pad)),
            base64char.x(2).pl(base64pad),eol));
    static final ABNF base64fullline = REG.rule("base64fullline", base64char.x(64).pl(eol));
    static final ABNF strictbase64text = REG.rule("strictbase64text", base64fullline.x().pl(strictbase64finl));
    // ABNF (厳密)
    static final ABNF strictextualmsg = REG.rule("strictextualmsg", preeb.pl(eol, strictbase64text, posteb, eol));
    
}
