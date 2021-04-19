package net.siisise.abnf.rfc;

import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;

/**
 * IETF Language Tag
 * IETF言語タグ
 * RFC 5646
 * RFC 4647
 * BCP 47
 * 
 * RFC 5646のABNFをコード化しただけ
 * 
 */
public class Lang5646 {
    static final ABNFReg REG = new ABNFReg(ABNF5234.BASE);

    static ABNF alphanum = REG.rule("alphanum", ABNF5234.ALPHA.or(ABNF5234.DIGIT));
    static ABNF regular = REG.rule("regular", "\"art-lojban\" / \"cel-gaulish\" / \"no-bok\" / \"no-nyn\" / \"zh-guoyu\" / \"zh-hakka\" / \"zh-min\" / \"zh-min-nan\" / \"zh-xiang\"");
    static ABNF irregular = REG.rule("irregular","\"en-GB-oed\" / \"i-ami\" / \"i-bnn\" / \"i-default\" / \"i-enochian\" / \"i-hak\" / \"i-klingon\" / \"i-lux\" / \"i-mingo\""
     + " / \"i-navajo\" / \"i-pwn\" / \"i-tao\" / \"i-tay\" / \"i-tsu\" / \"sgn-BE-FR\" / \"sgn-BE-NL\" / \"sgn-CH-DE\"");
    static ABNF grandfathered = REG.rule("grandfathered", irregular.or(regular));
    static ABNF privateuse = REG.rule("privateuse", "\"x\" 1*(\"-\" (1*8alphanum))");
    static ABNF singleton = REG.rule("singleton", ABNF5234.DIGIT.or(ABNF.range(0x41,0x57),ABNF.range(0x59,0x5A), ABNF.range(0x61, 0x77), ABNF.range(0x79,0x7a)));
    static ABNF extension = REG.rule("extension", singleton.pl(ABNF.bin('-').pl(alphanum.x(2,8)).ix()));
    static ABNF variant = REG.rule("variant", alphanum.x(5,8).or(ABNF5234.DIGIT.pl(alphanum.x(3,3))));
    static ABNF region = REG.rule("region", ABNF5234.ALPHA.x(2,2).or(ABNF5234.DIGIT.x(3,3)));
    static ABNF script = REG.rule("script", ABNF5234.ALPHA.x(4,4));
    static ABNF extlang = REG.rule("extlang", ABNF5234.ALPHA.x(3,3).pl(ABNF.bin('-').pl(ABNF5234.ALPHA.x(3,3)).x(0,2))); // selected ISO 639 codes perfmanently reserved
    static ABNF language = REG.rule("language", "2*3ALPHA [\"-\" extlang] / 4ALPHA / 5*8ALPHA");
    static ABNF langtag = REG.rule("langtag","language [\"-\" script] [\"-\" region] *(\"-\" variant) *(\"-\" extension) [\"-\" privateuse]");
    static ABNF Language_Tag = REG.rule("Language-Tag", langtag.or(privateuse, grandfathered));

}
