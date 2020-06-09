package net.siisise.abnf.jprs;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;

/**
 * ABNFによる都道府県型JPドメイン名の定義 改訂: 2014年 9月 1日.
 * https://jprs.jp/doc/rule/saisoku-1-prefecturejp-furoku-5.html
 * ファイルから読み込むことにする.
 */
public class PrefectureJPDN {

    public static ABNFReg REG = new ABNFReg();

    public static ABNF prefectureJPDN;
    
    static {
        try {
            REG.rulelist(PrefectureJPDN.class.getResource("prefectureJPDN.abnf"));
            prefectureJPDN = REG.href("prefecture-JPDN");
        } catch (IOException ex) {
            Logger.getLogger(PrefectureJPDN.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
