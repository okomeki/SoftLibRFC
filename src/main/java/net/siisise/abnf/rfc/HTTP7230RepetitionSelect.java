package net.siisise.abnf.rfc;

import net.siisise.bnf.BNF;
import net.siisise.bnf.BNFReg;
import net.siisise.bnf.parser.BNFSelect;

/**
 *
 */
public class HTTP7230RepetitionSelect extends BNFSelect {

    public HTTP7230RepetitionSelect(BNF abnf, BNFReg base) {
        super(abnf, base, "httprepetition", "orgrepetition");
    }

}
