# Git
[git@github.com:orlp/ed25519.git](https://github.com/orlp/ed25519)

# 说明
稍微调整了一下，瞎做成一个命令行程序方便用这个项目的各种功能。
```
Usage:
SHA512: ed25519 -sha512 -file/-string <file>/<string> [-o <file>]
ED25519: ed25519 [-ed25519] -seed [-o <file>]
ED25519: ed25519 [-ed25519] -keypair -i <file> [-publ-o <file> -priv-o <file>]
ED25519: ed25519 [-ed25519] -sign -i -file/-string <file>/<string> -publ-i <file> -priv-i <file> [-o <file>]
ED25519: ed25519 [-ed25519] -verify -i -file/-string <file>/<string> -publ-i <file> -sign-i <file>
ED25519: ed25519 [-ed25519] -add-scalar -publ-i <file>/NULL -priv-i <file>/NULL -scalar-i <file> [-publ-o <file> -priv-o <file>]
ED25519: ed25519 [-ed25519] -key-exchange -publ-i <file> -priv-i <file> [-o <file>]
```

# -seed
```
>ed25519 -seed
755FB4113651F8FDC9991703CEFB77D0E2BDCA8DECA3D0FA3EC5423391898899
```

# -keypair
```
>ed25519 -seed -o seed.bin
>ed25519 -keypair -i seed.bin
Public Key: 7AB53176218A4196BEE65CCD534701949C03CB648F92BDA9098321A132EA3A8B
Private Key: 88FF944389D74DD1E676180C0D2E8E021CB4FEB861D958CFF5A81B61A2E317559A6F25AE0C93D2989D0BD0CD6EB34B18B54869FD0F86DC34217F7B169F9ED9B5
```

# -sign
```
>ed25519 -seed -o seed.bin
>ed25519 -keypair -i seed.bin -publ-o publ.bin -priv-o priv.bin
>ed25519 -sign -i -string 123456 -publ-i publ.bin -priv-i priv.bin
EA96D23CBF8A15FA00FACD2DB9D79238DB7CE18D596806F80111E4C57C1AFAA1D43E7C4B89635867ECA1584A52A764C7194ABF6884C71962F1116E29D2CA7709
```

# -verify
```
>ed25519 -seed -o seed.bin
>ed25519 -keypair -i seed.bin -publ-o publ.bin -priv-o priv.bin
>ed25519 -sign -i -string 123456 -publ-i publ.bin -priv-i priv.bin -o sign.bin
>ed25519 -verify -i -string 123456 -publ-i publ.bin -sign-i sign.bin
TRUE
```

# -add-scalar
```
>ed25519 -seed -o seed.bin
>ed25519 -seed -o scalar.bin
>ed25519 -keypair -i seed.bin -publ-o publ.bin -priv-o priv.bin
>ed25519 -add-scalar -publ-i publ.bin -priv-i priv.bin -scalar-i scalar.bin
Public Key: EB87C78BE8F802670A9D41E48EF6A47BA2D627F86AA45C57CE21575C8C290B4C
Private Key: CD772247D3E5CD6B6FA9DF9543CAB75354A98D0C63AC65C1558BB32006AF4E083868D34F9967018EF5D6EFC3294B93936C3871010E535D2A9FFE9C8958DBE3B9
```

# -key-exchange
```
>ed25519 -seed -o seed.bin
>ed25519 -seed -o seed2.bin
>ed25519 -keypair -i seed.bin -publ-o publ.bin -priv-o priv.bin
>ed25519 -keypair -i seed2.bin -publ-o publ2.bin -priv-o priv2.bin
>ed25519 -key-exchange -publ-i publ.bin -priv-i priv2.bin
Shared Secret: 5FDF0F2048C573989E5BA02FDB94A5C544D7C14A959278225CA69C094A45FA12
>ed25519 -key-exchange -publ-i publ2.bin -priv-i priv.bin
Shared Secret: 5FDF0F2048C573989E5BA02FDB94A5C544D7C14A959278225CA69C094A45FA12
```

>注意！如果两个秘钥有`-add-scalar`关系（不对称），并不能正确得到共享私钥，不要用这种密钥对尝试共享私钥。

```
>ed25519 -seed -o seed.bin
>ed25519 -seed -o scalar.bin
>ed25519 -keypair -i seed.bin -publ-o publ.bin -priv-o priv.bin
>ed25519 -add-scalar -publ-i publ.bin -priv-i priv.bin -scalar-i scalar.bin -publ-o publ2.bin -priv-o priv2.bin
>ed25519 -key-exchange -publ-i publ.bin -priv-i priv2.bin
Shared Secret: 038CA8EE9251A5919A2AB3886464256BFD12D9B1E4602D39B4E7CF6E071BC575
>ed25519 -key-exchange -publ-i publ2.bin -priv-i priv.bin
Shared Secret: 024203EC447EFF16ADC4FBE6C950B64434CF74BDC20B1D05771DCC3EA099F364
```
