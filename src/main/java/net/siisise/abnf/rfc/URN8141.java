package net.siisise.abnf.rfc;

import java.nio.charset.StandardCharsets;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import net.siisise.block.ReadableBlock;
import net.siisise.bnf.BNF;
import net.siisise.io.Packet;

/**
 * Uniform Resource Name.
 * RFC 1737 Functional Requirements for Uniform Resource Names
 * RFC 2141 URN Syntax 8141により廃止
 * RFC 3406 Uniform Resource Names (URN) Namespace Definition Mechanisms 8141により廃止
 * RFC 3986 URI
 * RFC 8141 Uniform Resource Names (URNs)
 *
 */
public class URN8141 {

    static final ABNFReg REG = new ABNFReg();

    static final ABNF alphanum = REG.rule("alphanum", ABNF5234.ALPHA.or(ABNF5234.DIGIT));
    static final ABNF fragment = REG.rule("fragment", URI3986.fragment);
    static final ABNF pchar = REG.rule("pchar", URI3986.pchar);

    static final ABNF DigitNonZero = REG.rule("DigitNonZero", ABNF.range('1', '9'));
    static final ABNF Digit = REG.rule("Digit", "\"0\" / DigitNonZero");
    static final ABNF Number = REG.rule("Number", "DigitNonZero 0*Digit");
    public static final ABNF InformalNamespaceName = REG.rule("InformalNamespaceName", "\"urn-\" Number");

    static final ABNF fComponent = REG.rule("f-component", fragment);
    static final ABNF qComponent = REG.rule("q-component", "pchar *( pchar / \"/\" / \"?\" )");
    static final ABNF rComponent = REG.rule("r-component", "pchar *( pchar / \"/\" / \"?\" )");
    static final ABNF rqComponents = REG.rule("rq-components", "[ \"?+\" r-component ] [ \"?=\" q-component ]");
    /**
     * 名前空間固有文字列 (Namespace Specific String)
     */
    static final ABNF NSS = REG.rule("NSS", "pchar *(pchar / \"/\")");
    static final ABNF ldh = REG.rule("ldh", alphanum.or(ABNF.bin('-')));
    /**
     * 名前空間識別子 (Namespace Identifier)
     */
    static final ABNF NID = REG.rule("NID", "(alphanum) 0*30(ldh) (alphanum)");
    static final ABNF assignedName = REG.rule("assigned-name", "\"urn\" \":\" NID \":\" NSS");
    public static final ABNF namestring = REG.rule("namestring", "assigned-name [ rq-components ] [ \"#\" f-component ]");

    private String urn;
    
    public URN8141(String urn) {
        this.urn = urn;
    }
    
    public String getNID() {
        ReadableBlock rurn = ReadableBlock.wrap(urn);
        BNF.Match<Packet> r = REG.find(rurn, "namestring", "NID");
        return new String(r.get("NID").get(0).toByteArray(), StandardCharsets.UTF_8);
    }
}
