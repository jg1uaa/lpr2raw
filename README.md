# lpr $B"*(B raw (HP JetDirect/AppSocket) $B%W%m%H%3%kJQ49(B

---
## $B@bL@(B

$BD64A;z$O(B LPD $B%W%m%H%3%k$N%M%C%H%o!<%/%W%j%s%?$KBP1~$9$k$b$N$N!"(Braw $B%W%m%H%3%k$N%W%j%s%?$K$OBP1~$7$J$$$?$a!"30It$K(B LPRng $BEy$NF0:n$9$k%5!<%P$rMQ0U$7$FJQ49$9$kI,MW$,$"$j$^$9!#(B

$B$3$l$r:n@.$7$?(B 2024 $BG/$K$*$$$F$O(B LPRng $B$G$O$J$/(B CUPS $B$,<gN.$H$J$C$F$$$^$9$,!"(BLPD $B8_495!G=$rDs6!$9$k(B CUPS-lpd $B$rN)$A>e$2$k$N$O$A$g$C$HLLE]$G$9!#(B

$B$=$3$G!"D64A;z>e$G(B LPD $B%5!<%P$H$7$F?6$kIq$$!"0u:~%G!<%?$r(B raw $B%W%m%H%3%k$KJQ49$7$F%W%j%s%?$KAw?.$9$k$b$N$r:n@.$7$F$_$^$7$?!#(B

**$BD64A;z$NF0:n$9$k%^%7%s$O%U%!%$%"%&%)!<%kEy$GJ]8n$5$l$?%M%C%H%o!<%/4D6-2<$K$"$k$3$H$rA0Ds$H$7$F$$$^$9!#(B**

## $B;HMQJ}K!(B

```
% lpr2raw -h
usage: lpr2raw -a [ip address] -p [portnum]
%
```

$B%X%k%W%a%C%;!<%8$NI=<($O(B `-h` $B%*%W%7%g%s$rI,$:;XDj$7$F$/$@$5$$!#(B
`-a` $B$K%M%C%H%o!<%/%W%j%s%?$N(B IP $B%"%I%l%9!J>JN,;~$O(B localhost $B$H$7$F07$$$^$9!K!"(B`-p` $B$K%]!<%HHV9f!J>JN,;~$O(B 9100 $B$H$7$F07$$$^$9!K$r;XDj$7$^$9!#(B

$BD64A;z$N%W%j%s%?@_Dj$O(B

- $B5!<o!'$*;H$$$N5!<o$K9g$o$;$?$b$N(B
- $B=PNO@h!'%M%C%H%o!<%/(B
- $B=PNO@_Dj!'%W%m%H%3%k$O(B LPDP$B!"%[%9%HL>$O(B `localhost`$B!"%-%e!<L>$OG$0U!J6uMs2D!K(B

$B$H$7$F$/$@$5$$!#(B

$B$"$H$ODL>o$N0u:~A`:n$r9T$&$3$H$G!"(Blpr2raw $B$K;XDj$7$?%W%j%s%?$N(BIP$B%"%I%l%9!&%]!<%H$K%G!<%?Aw?.$r9T$$$^$9!#(B

### $B;HMQNc(B

```
% lpr2raw -a 192.168.0.192
```

raw $B%W%m%H%3%k$KBP1~$7$?%W%j%s%?$NBe$o$j$K!"(BLinux $B5!Ey$G(B `nc -h 9100 > out.prn` $B$K$h$k0u:~%G!<%?$N<u?.$H$$$C$?;H$$J}$b$G$-$k$G$7$g$&!#(B

## $B@)8B;v9`(B

- $B<h$j07$$2DG=$J0u:~%G!<%?$N>e8B%5%$%:$O(B 0x7fffffff $B%P%$%H$G$9(B
- LPDP$B!J4J0W!K$K$OHsBP1~$G$9(B
- $B30It$N%M%C%H%o!<%/$+$i$N(B LPD $B"*(B raw $BJQ49MW5a$b<u$1IU$1$F$7$^$$$^$9(B

$B$3$l$i$r2~A1$9$kM=Dj$O$"$j$^$;$s!#(B

## $B%i%$%;%s%9(B

WTFPL (http://www.wtfpl.net/) $B$K=`5r$7$^$9!#(B
