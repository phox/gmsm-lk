# license-key (国密 SM2/SM3 版本)


A simple licensing library in Golang, that generates license files containing
arbitrary data (ex: user email, end date...) that you can further validate if you want.

**本项目基于(https://github.com/hyperboloide/lk/)已改造为使用国密算法：**
- **签名算法**: SM2 (基于 sm2p256v1 曲线，符合 GM/T 0003-2012 标准)
- **哈希算法**: SM3 (符合 GM/T 0004-2012 标准)
- **依赖库**: [github.com/emmansun/gmsm](https://github.com/emmansun/gmsm)

The license file can be marshalled in an easy to distribute format (ex: base32 encoded strings)

Note that this implementation is quite basic and that in no way it could
prevent someone to hack your software. The goal of this project is only
to provide a convenient way for software publishers to generate license keys
and distribute them without too much hassle for the user.

### 与原版的区别

| 原版 (ECDSA) | 本版 (SM2) |
|------------|----------|
| 使用 NIST P-384 曲线 | 使用国密 sm2p256v1 曲线 |
| 使用 SHA-256 哈希 | 使用 SM3 哈希 |
| 依赖 crypto/ecdsa | 依赖 github.com/emmansun/gmsm/sm2 |
| 依赖 crypto/sha256 | 依赖 github.com/emmansun/gmsm/sm3 |

### How does it works?

1. Generate a private key (and keep it secure).
2. Transform the data you want to provide (end date, user email...) to a byte array (using json or gob for example).
3. The library takes the data and create a cryptographically signed hash using SM2/SM3 that is appended to the data.
4. Convert the result to a Base64/Base32/Hex string and send it to the end user: this is the license.
5. When the user starts your program load the license and verify the signature using a public key.
6. Validate the data in your license key (ex: the end date)


### lkgen

A command line helper [lkgen](lkgen) is also provided to generate private keys and create licenses.

This is also a good example of how to use the library.

### Examples

#### Generating a new license:

Below is an example of code that generates a license from a private key and a struct containing the end date and a user email that is marshalled to json.

```go
// Generate a new SM2 private key
// In production, you should save this key and load it from a file
privateKey, err := lk.NewPrivateKey()
if err != nil {
	log.Fatal(err)
}

// Save the private key (base32 encoded) for future use
privateKeyB32, err := privateKey.ToB32String()
if err != nil {
	log.Fatal(err)
}
fmt.Println("Private Key:", privateKeyB32)

// Define the data you need in your license,
// here we use a struct that is marshalled to json, but ultimately all you need is a []byte.
doc := struct {
	Email string    `json:"email"`
	End   time.Time `json:"end"`
}{
	"user@example.com",
	time.Now().Add(time.Hour * 24 * 365), // 1 year
}

// marshall the document to []bytes (this is the data that our license will contain).
docBytes, err := json.Marshal(doc)
if err != nil {
	log.Fatal(err)
}

// generate your license with the private key and the document
license, err := lk.NewLicense(privateKey, docBytes)
if err != nil {
	log.Fatal(err)
}

// the b32 representation of our license, this is what you give to your customer.
licenseB32, err := license.ToB32String()
if err != nil {
	log.Fatal(err)
}
fmt.Println("License:", licenseB32)
```

#### Validating a license:

Before your execute your program you want to check the user license:

```go
// The public key should be hardcoded in your app (generated from private key)
// You can get it using: privateKey.GetPublicKey().ToB32String()
const publicKeyBase32 = "YOUR_PUBLIC_KEY_HERE"

// A previously generated license b32 encoded (provided by the customer)
const licenseB32 = "CUSTOMER_LICENSE_HERE"

// Unmarshal the public key.
publicKey, err := lk.PublicKeyFromB32String(publicKeyBase32)
if err != nil {
	log.Fatal(err)
}

// Unmarshal the customer license.
license, err := lk.LicenseFromB32String(licenseB32)
if err != nil {
	log.Fatal(err)
}

// validate the license signature using SM2.
if ok, err := license.Verify(publicKey); err != nil {
	log.Fatal(err)
} else if !ok {
	log.Fatal("Invalid license signature")
}

result := struct {
	Email string    `json:"email"`
	End   time.Time `json:"end"`
}{}

// unmarshal the document.
if err := json.Unmarshal(license.Data, &result); err != nil {
	log.Fatal(err)
}

// Now you just have to check that the end date is after time.Now() then you can continue!
if result.End.Before(time.Now()) {
	log.Fatalf("License expired on: %s", result.End.Format("2006-01-02"))
} else {
	fmt.Printf(`Licensed to %s until %s`, result.Email, result.End.Format("2006-01-02"))
}
```


#### A Complete example

Bellow is a sample function that generate a key pair, signs a license and verify it.

```go
// create a new SM2 Private key:
privateKey, err := lk.NewPrivateKey()
if err != nil {
	log.Fatal(err)
}

// create a license document:
doc := MyLicence{
	"test@example.com",
	time.Now().Add(time.Hour * 24 * 365), // 1 year
}

// marshall the document to json bytes:
docBytes, err := json.Marshal(doc)
if err != nil {
	log.Fatal(err)
}

// generate your license with the private key and the document (signed using SM2/SM3):
license, err := lk.NewLicense(privateKey, docBytes)
if err != nil {
	log.Fatal(err)
}

// encode the new license to b64, this is what you give to your customer.
str64, err := license.ToB64String()
if err != nil {
	log.Fatal(err)
}
fmt.Println(str64)

// get the public key. The public key should be hardcoded in your app to check licences.
// Do not distribute the private key!
publicKey := privateKey.GetPublicKey()

// validate the license using SM2:
if ok, err := license.Verify(publicKey); err != nil {
	log.Fatal(err)
} else if !ok {
	log.Fatal("Invalid license signature")
}

// unmarshal the document and check the end date:
res := MyLicence{}
if err := json.Unmarshal(license.Data, &res); err != nil {
	log.Fatal(err)
} else if res.End.Before(time.Now()) {
	log.Fatalf("License expired on: %s", res.End.String())
} else {
	fmt.Printf(`Licensed to %s until %s \n`, res.Email, res.End.Format("2006-01-02"))
}
```

### 国密算法说明

本项目使用的国密算法：

- **SM2**: 椭圆曲线公钥密码算法，用于数字签名。基于 sm2p256v1 曲线，安全性等同于 NIST P-256。
- **SM3**: 密码杂凑算法，输出 256 位哈希值，安全性等同于 SHA-256。

更多关于国密算法的信息，请参考：
- [GM/T 0003-2012 SM2椭圆曲线公钥密码算法](http://www.gmbz.org.cn/)
- [GM/T 0004-2012 SM3密码杂凑算法](http://www.gmbz.org.cn/)
- [gmsm 库文档](https://emmansun.github.io/gmsm/)
