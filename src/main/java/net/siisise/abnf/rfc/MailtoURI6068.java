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
 * RFC 6068 The 'mailto' URI Scheme
 */
public class MailtoURI6068 {
    
    public static final ABNFReg REG = new ABNFReg();
    
    // STD 66 RFC 3986 https://www.rfc-editor.org/info/std66 URI
            
    static final ABNF unreserved = REG.rule("unreserved",URI3986.unreserved);
    static final ABNF pct_encoded = REG.rule("pct-encoded", URI3986.pctEncoded);
    static final ABNF dot_atom_text = REG.rule("dot-atom", IMF5322.dotAtomText);
    static final ABNF quoted_string = REG.rule("quoted-string", IMF5322.quotedString);
    static final ABNF some_delims = REG.rule("some-delims", ABNF.binlist("!$'()*+,;:@"));
    static final ABNF qchar = REG.rule("gchar", unreserved.or(pct_encoded, some_delims));
    static final ABNF dtext_no_obs = REG.rule("dtext_no_obs", ABNF.range(33, 90).or(ABNF.range(94,126)));
    static final ABNF domain = REG.rule("domain", dot_atom_text.or(ABNF.bin('[').pl(dtext_no_obs.x(), ABNF.bin(']'))));
    static final ABNF local_part = REG.rule("local-part", dot_atom_text.or(quoted_string));
    static final ABNF addr_spec = REG.rule("addr-spec", local_part.pl(ABNF.bin('@'), domain));
    static final ABNF hfname = REG.rule("hfname", qchar.x());
    static final ABNF hfvalue = REG.rule("hfvalue", qchar.x());
    public static final ABNF hfield = REG.rule("hfield", hfname.pl(ABNF.bin('='),hfvalue));
    public static final ABNF hfields = REG.rule("hfields", ABNF.bin('?').pl(hfield, ABNF.bin('&').pl(hfield).x()) );
    public static final ABNF to = REG.rule("to", addr_spec.pl( ABNF.bin(',').pl(addr_spec).x()));
    public static final ABNF mailtoURI = REG.rule("mailtoURI", ABNF.text("mailto:").pl(to.c(), hfields.c()));
    
}
