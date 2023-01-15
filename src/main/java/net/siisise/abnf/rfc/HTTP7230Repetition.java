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

import java.util.List;
import net.siisise.abnf.ABNF;
import net.siisise.bnf.BNF;
import net.siisise.bnf.BNFReg;
import net.siisise.bnf.parser.BNFBuildParser;
import net.siisise.io.FrontPacket;

/**
 * RFC 7230 7.
 * RFC 9110 5.6.1.1. もおなじ 5.6.1.2. 未実装かも
 * ABNFを拡張する
 */
public class HTTP7230Repetition extends BNFBuildParser<ABNF, Object> {

    public HTTP7230Repetition(BNF rule, BNFReg base) {
        super(rule, base, "rep-list","element");
    }

    /**
     * 1#element -&lt; element *( OWS "," OWS element )
     * #element -&lt; [ 1#element ] -&lt; [ element *( OWS "," OWS element ) ]
     * n&gt;=1 , m&gt;1 に対し
     * &gt;n&lt;#&gt;m&lt;element -&lt; element &gt;n-1&lt;*&gt;m-1&lt;( OWS "," OWS element )
     *
     * @param ret
     * @return
     */
    @Override
    protected ABNF build(ABNF.Match<Object> ret) {        
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
