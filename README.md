# lpr → raw (HP JetDirect/AppSocket) プロトコル変換

---
## 説明

超漢字は LPD プロトコルのネットワークプリンタに対応するものの、raw プロトコルのプリンタには対応しないため、外部に LPRng 等の動作するサーバを用意して変換する必要があります。

これを作成した 2024 年においては LPRng ではなく CUPS が主流となっていますが、LPD 互換機能を提供する CUPS-lpd を立ち上げるのはちょっと面倒です。

そこで、超漢字上で LPD サーバとして振る舞い、印刷データを raw プロトコルに変換してプリンタに送信するものを作成してみました。

**超漢字の動作するマシンはファイアウォール等で保護されたネットワーク環境下にあることを前提としています。**

## 使用方法

```
% lpr2raw -h
usage: lpr2raw -a [ip address] -p [portnum]
%
```

ヘルプメッセージの表示は `-h` オプションを必ず指定してください。
`-a` にネットワークプリンタの IP アドレス（省略時は localhost として扱います）、`-p` にポート番号（省略時は 9100 として扱います）を指定します。

超漢字のプリンタ設定は

- 機種：お使いの機種に合わせたもの
- 出力先：ネットワーク
- 出力設定：プロトコルは LPDP、ホスト名は `localhost`、キュー名は任意（空欄可）

としてください。

あとは通常の印刷操作を行うことで、lpr2raw に指定したプリンタのIPアドレス・ポートにデータ送信を行います。

### 使用例

```
% lpr2raw -a 192.168.0.192
```

raw プロトコルに対応したプリンタの代わりに、Linux 機等で `nc -h 9100 > out.prn` による印刷データの受信といった使い方もできるでしょう。

## 制限事項

- 取り扱い可能な印刷データの上限サイズは 0x7fffffff バイトです
- LPDP（簡易）には非対応です
- 外部のネットワークからの LPD → raw 変換要求も受け付けてしまいます

これらを改善する予定はありません。

## ライセンス

WTFPL (http://www.wtfpl.net/) に準拠します。
