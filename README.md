# opencloud

AWS、Azure、GCPのcontrol-plane APIを、**実際のwire形式で**答えるlocal server。
cloud posture / CSPM / inventory clientを、認証情報も課金もなしに検証するための
ものである。

## なぜ `com-aws` ではないのか

`kotoba-lang/com-aws`、`com-azure`、`com-gcp` は既に存在するが、それらは
汎用L4 actorのCRUD面（`/v1/ec2instances` にJSON）である。実APIとは形が違う。

- 実EC2は `Action=DescribeInstances&Version=2016-11-15` にSigV4署名、応答はXML
- 実IAMは同じくquery protocol、listは `<member>`。EC2は `<item>`
- 実S3はRESTでsubresource（`?policyStatus`）、errorのenvelopeも別物

REST+JSONへ置き換えたAPIは、**clientが間違える箇所をすべて消してしまう**ので
検証にならない。このrepositoryはその差分を保つことだけを目的にしている。
`com-*` actorとは目的が異なるので同居させず、別名にしてある。

## 何を検証できるか

**署名を検証する。** 未署名requestは401、署名が合わなければ403 `SignatureDoesNotMatch`
を返す。署名を検証しないserverはfixtureであってverification targetではない
（clientが何も署名しなくても通ってしまう）。

SigV4のverifierは**意図的に独立実装**であり、どのclientともcodeを共有しない。
署名側と検証側が正準化を共有していれば、両者は構造上必ず一致するので何も
証明しない。仕様から別々に書いた2つの実装は、どちらかが間違っている箇所で
必ず食い違う。それがこのserverに署名を通す価値である。

verifierはJVM側のtestで、公開されているAWS Signature V4 test suite
(`get-vanilla`)の署名を**受理する**ことを確認している。clientは同じvectorに
対して署名を**生成**して確認する。両側から同じ既知解に当てている。

## 実行

```sh
npm start                      # port 4566（OPENCLOUD_PORT で変更可）
kbb --backend sci --classpath src:resources -m opencloud.server --port 4599 --verbose true
npm test                       # JVM上のportable部分のtest
```

`--verbose true` を付けると署名不一致時にserverが計算したcanonical request
を出力する。client側のbugを見つけるとき、これが無いと手掛かりがない。

clientはendpointを差し替えて向ける。署名はAWS宛と同一のまま送るので、
**signerのbugはそのまま表面化する。**

```sh
export AWS_ACCESS_KEY_ID=AKIAOPENCLOUDEXAMPLE
export AWS_SECRET_ACCESS_KEY=opencloudExampleSecretKeyNotUsableAnywhereReal
export AI_GFTD_AWS_ENDPOINT=http://127.0.0.1:4599   # client側のendpoint override
```

上の認証情報は**公開されているもので、秘密ではない**。verification targetで
あって認証情報の保管庫ではない。

## 実装範囲

| provider | auth | 実装済み |
|---|---|---|
| AWS | SigV4検証 | sts:GetCallerIdentity、ec2 5 action、s3 6 subresource、iam 14 action、rds:DescribeDBInstances |
| Azure | bearer token、`api-version`必須 | virtualMachines、storageAccounts、roleAssignments |
| GCP | bearer token | compute instances、storage buckets、project IAM policy |

AWSはpaginationも実際のtokenで行う。EC2/RDSは `nextToken`、IAMは
`IsTruncated` + `Marker` で、seedの `:page-size` を小さくしてあるので
**既定で複数ページになる**。1ページ目しか読まないclientはここで落ちる。

未実装のoperationは、空の成功ではなく `InvalidAction` / `ResourceNotFound` を
返す。空の成功はclientから見て「そのresourceが無い」と区別が付かない。

## seed

`resources/seed/*.edn` は決定論的なaccountである。内容は恣意的ではなく、
**完全な権限昇格の連鎖**を含むように選んである。

```
i-web (public, IMDSv1)
  └─ instance profile ─▶ web-role
        └─ trust policy ─▶ deploy-role
              └─ bucket policy ─▶ payroll-archive  (tag sensitive=true)
```

加えて、誰でもassumeできるrole、ExternalId無しのcross-account trust、
外部accountへ共有されたbucket、暗号化もbackupも無いdatabase、
一度も使われていないaccess key、`NotAction`によるallowを含む。

**これを全部見つけられないclientにはgapがある。** JVM側のtestが、seedが
この連鎖を持ち続けていることを検査する（seedが崩れれば、そこを通るclientは
見かけより少ないことしか証明していない）。

## 見つかったもの

ai-gftd-cybersecurity のposture connectorをこのserverに通して、実際に
3件のbugが出た。いずれも記録済みresponseに対するunit testでは出なかった。

1. `:services` にnilが渡ると収集対象が空になり、**空のaccountを成功として
   返していた**（`:or` はkeyが無いときしか効かない）
2. roleに対して「一度も使われていないcredential」を報告していた。roleは
   access keyを持たないので、報告すべきものが存在しない
3. S3のtagを `<item>` で読もうとしていた。実際は `<Tag>` であり、
   crown jewelを示すtagが落ちて **attack pathが1本も出なかった**

3つ目が最も悪い形である。結果が間違っていたのではなく、静かに空になった。

そして4件目 ── **SigV4署名がNode上で秘密鍵をほぼ無視していた。**

`(map int "AWS4…")` はJVMでは文字のcode pointだが、ClojureScriptでは文字が
1文字の文字列なので `int` は0へ潰す（数字だけが残る）。signing keyが
ほぼ定数のbyte列から導出されるため、**どの秘密鍵でも同じ署名**になる。

これはclientとserverの両方に同じ形で入っていた。codeは共有していないが
idiomを共有していた。結果、両者は互いに一致し、JVMのtest vectorも通り、
serverも受理し、**誤った秘密鍵ですら成功した**。実AWSに対しては全requestが
SignatureDoesNotMatchになる。

このrepositoryのREADMEは冒頭で「正準化を共有する署名側と検証側は構造上必ず
一致するので何も証明しない」と書いた。共有していたのはcodeではなく前提
だったが、結果は同じだった。**両側を同じ公開vectorに、かつ実行するruntimeの
上で当てる**ことでしか捕まらない。conformance testは「誤った秘密鍵が拒否
されること」を確認する ── これが通らなければ、他の全assertionは無意味である。
