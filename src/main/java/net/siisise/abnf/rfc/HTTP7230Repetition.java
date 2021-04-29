package net.siisise.abnf.rfc;

import java.util.List;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser.ABNFBuildParser;
import net.siisise.io.FrontPacket;

/**
 * RFC 7230 7.
 */
public class HTTP7230Repetition extends ABNFBuildParser<ABNF, Object> {

    public HTTP7230Repetition(ABNF rule, ABNFReg reg, ABNFReg base) {
        super(rule, reg, base, "rep-list","element");
    }

    /**
     * 1#element -> element *( OWS "," OWS element )
     * #element -> [ 1#element ] -> [ element *( OWS "," OWS element ) ]
     * n>=1 , m>1 に対し
     * <n>#<m>element -> element <n-1>*<m-1>( OWS "," OWS element )
     *
     * @param ret
     * @return
     */
    @Override
    protected ABNF build(ABNF.C<Object> ret) {        
        List<Object> rep = ret.get(HTTP7230.repList);
        ABNF element = (ABNF) ret.get("element").get(0);
//        System.out.println("ee;:" + strd(element));
        //ABNF ele = subs[0].parse(element);
        if (rep != null) {
            return repeat(str((FrontPacket)rep.get(0)), element);
        }
        return element;
    }

    ABNF repeat(String repeat, ABNF element) {
        if (repeat.contains("#")) {
            int off = repeat.indexOf("#");
            String l = repeat.substring(0, off);
            String r = repeat.substring(off + 1);
            if (l.isEmpty()) {
                l = "0";
            }
            if (r.isEmpty()) {
                r = "-1";
            }
            int n = Integer.parseInt(l);
            int m = Integer.parseInt(r);
            if (n == 0 && m == -1) {
                return element.pl(HTTP7230.OWS.pl(ABNF.bin(","), HTTP7230.OWS, element).x()).c();
            } else if (n == 1 && m == -1) {
                return element.pl(HTTP7230.OWS.pl(ABNF.bin(","), HTTP7230.OWS, element).x());
            } else if (n >= 1 && m > 1) {
                return element.pl(HTTP7230.OWS.pl(ABNF.bin(","), HTTP7230.OWS, element).x(n - 1, m - 1));
            } else {
                // null ?
            }
            return null;
        } else {
            int r = Integer.parseInt(repeat);
            ABNF ex = element;
            return ex.x(r, r);
        }
    }
}
