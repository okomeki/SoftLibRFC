# SoftLibRFC
RFC ABNF Parse Tools

ABNF ParserにRFC系の書式を乗せたもの。
パース順序の関係で若干の変更はあるが、RFCから解釈が変わるような変更はない。

* RFC 3987 IRI
* RFC 5322 Internet Message Format
* RFC 6749 OAuth
* RFC 6874 URI
* RFC 7230 HTTP
* RFC 7235 HTTP Authentication
* RFC 9110 HTTP Semantics.
* RFC 9112 HTTP/1.1

などがparse可能

## Maven
module非対応 Java 1.8版
~~~
<dependency>
  <groupId>net.siisise</groupId>
  <artifactId>softlib-rfc</artifaceId>
  <version>1.0.2</version>
  <type>jar</type>
</dependency>
~~~
module対応 Java 11版
~~~
<dependency>
  <groupId>net.siisise</groupId>
  <artifactId>softlib-rfc.module</artifaceId>
  <version>1.0.2</version>
  <type>jar</type>
</dependency>
~~~

リリース版 1.0.3 ぐらい。

## Module
~~~
net.siisise.abnf.rfc
~~~