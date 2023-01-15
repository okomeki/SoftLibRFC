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
 * IETF Language Tag
 * IETF言語タグ
 * RFC 4646 RFC 5646
 * RFC 4647
 * BCP 47
 * 
 * RFC 4646のABNFをコード化しただけ
 * 
 * @author okome
 */
public class Lang4646 {
    static final ABNFReg REG = new ABNFReg(ABNF5234.BASE);

    static ABNF alphanum = REG.rule("alphanum", ABNF5234.ALPHA.or(ABNF5234.DIGIT));
    static ABNF grandfathered = REG.rule("grandfathered", ABNF5234.ALPHA.x(1,3).pl(ABNF.bin('-').pl(alphanum.x(2,8)).x(1,2)));
    static ABNF privateuse = REG.rule("privateuse", "(\"x\"/\"X\") 1*(\"-\" (1*8alphanum))");
    static ABNF singleton = REG.rule("singleton", ABNF.range(0x41,0x57).or(ABNF.range(0x59,0x5A), ABNF.range(0x61, 0x77), ABNF.range(0x79,0x7a), ABNF5234.DIGIT));
    static ABNF extension = REG.rule("extension", singleton.pl(ABNF.bin('-').pl(alphanum.x(2,8)).ix()));
    static ABNF variant = REG.rule("variant", alphanum.x(5,8).or(ABNF5234.DIGIT.pl(alphanum.x(3,3))));
    static ABNF region = REG.rule("region", ABNF5234.ALPHA.x(2,2).or(ABNF5234.DIGIT.x(3,3)));
    static ABNF script = REG.rule("script", ABNF5234.ALPHA.x(4,4));
    static ABNF extlang = REG.rule("extlang", ABNF.bin('-').pl(ABNF5234.ALPHA.x(3,3)).x(0,3));
    static ABNF language = REG.rule("language", "(2*3ALPHA [ extlang ]) / 4ALPHA / 5*8ALPHA");
    static ABNF langtag = REG.rule("langtag","(language [ \"-\" script] [\"-\" region] *(\"-\" variant) *(\"-\" extension) [\"-\" privateuse])");
    static ABNF Language_Tag = REG.rule("Language-Tag", langtag.or( privateuse, grandfathered));
}
