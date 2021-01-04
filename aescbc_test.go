package encrypt

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
)

var _testKey = struct {
	Length16 [][]byte
	Length24 [][]byte
	Length32 [][]byte
}{
	Length16: [][]byte{
		[]byte("1234567812345678"),
		[]byte("8765432187654321"),
		[]byte("k2389anlk30sdnls"),
		[]byte("*@%%$JBDMdbkk1.:"),
		[]byte("#&!%jsbdk3735o./"),
		[]byte("lskfk2389O#&*jdn"),
		[]byte("7nsklkhdi3msmd,d"),
		{18, 12, 51, 183, 201, 34, 221, 171,
			81, 92, 127, 129, 91, 24, 71, 92},
		{37, 29, 18, 91, 27, 84, 48, 10,
			28, 47, 28, 94, 10, 38, 71, 39},
	},
	Length24: [][]byte{
		[]byte("123456781234567812345678"),
		[]byte("876543218765432187654321"),
		[]byte("kljdfl2724ojsksldfglkj30"),
		[]byte("LK@&77713lKnJEF,.;lewer2"),
		[]byte("&##7i23nmn,vaej.z/w;elkl"),
		[]byte(">>?2pdsk3912bksjf3y7skj3"),
		[]byte("NKJbsvjas23I3lksdb,pvarf"),
		{18, 12, 51, 81, 201, 38, 221, 171,
			81, 92, 51, 12, 91, 24, 71, 92,
			12, 92, 91, 28, 93, 18, 38, 21},
		{37, 29, 63, 91, 27, 84, 48, 10,
			28, 47, 93, 94, 10, 37, 71, 39,
			19, 41, 18, 40, 81, 73, 41, 31},
	},
	Length32: [][]byte{
		[]byte("12345678123456781234567812345678"),
		[]byte("87654321876543218765432187654321"),
		[]byte("kfj23&^*@rkglnv.,a;./>Kfjlwjrk23"),
		[]byte("2398^*333jsbvm,dd2illpa4izkln.sf"),
		[]byte("*^33jbavsja,mzlkepioooafkkj3kfam"),
		[]byte("vmnwj3kkLKSGNllmgsd,mfgkro2i3oij"),
		[]byte("Lnzmkjdh6%#^kajs?:mdoioookalsnvl"),
		{18, 12, 51, 81, 12, 38, 221, 171,
			82, 23, 51, 26, 82, 72, 71, 73,
			81, 92, 12, 12, 91, 24, 66, 92,
			12, 92, 91, 32, 93, 52, 38, 21},
		{37, 29, 63, 91, 27, 84, 48, 10,
			28, 223, 93, 66, 10, 37, 113, 42,
			221, 47, 23, 94, 111, 17, 71, 39,
			19, 41, 18, 40, 81, 73, 41, 31},
	},
}

var _testIv = [][]byte{
	[]byte("1234567812345678"),
	[]byte("8765432187654321"),
	[]byte("298jakjf7aoslkjs"),
	[]byte("<?#:SDkskdjfusdk"),
	[]byte("9837(%$!#73jhsdf"),
	[]byte("aksj73ksn40skn23"),
	{18, 12, 51, 183, 201, 34, 221, 171,
		81, 92, 127, 129, 91, 24, 71, 92},
	{37, 29, 18, 91, 27, 84, 48, 10,
		28, 47, 28, 94, 10, 38, 71, 39},
	{82, 17, 93, 12, 42, 72, 81, 21,
		82, 12, 93, 33, 41, 12, 44, 92},
	{38, 31, 48, 92, 49, 12, 49, 12,
		83, 23, 81, 39, 23, 12, 28, 39},
	nil,
}

var _testData = [][]byte{
	[]byte("1"),
	[]byte("12"),
	[]byte("123"),
	[]byte("1234"),
	[]byte("12345"),
	[]byte("123456"),
	[]byte("1234567"),
	[]byte("12345678"),
	[]byte("123456789"),
	[]byte("1234567890"),
	[]byte("1234567890-1"),
	[]byte("This is a message!"),
	[]byte("aksjdflieulasjd flajsldf"),
	{213, 12, 43, 12, 132, 128, 234, 62, 0, 2, 123, 171, 17, 71},
	{18, 127, 83, 19, 150, 172, 182, 129, 182},
	{0},
	{0, 0, 0, 0, 0, 0, 0},
	{1, 1, 1, 1, 1, 1},
	{255, 255, 255, 255},
}

var _testFile = []string{
	path.Join("file_test", "text2"),
	path.Join("file_test", "text.txt"),
	path.Join("file_test", "text.tgz"),
}

func TestAesCBC(t *testing.T) {
	for ik, k := range _testKey.Length16 {
		for ii, i := range _testIv {
			for id, d := range _testData {
				encrypted, err := AesCBCEncrypt(d, k, i)
				if err != nil {
					t.Errorf("16 encrypt [%d:%d:%d] error: %s\n", ik, ii, id, err)
					continue
				}

				decrypted, err := AesCBCDecrypt(encrypted, k, i)
				if err != nil {
					t.Errorf("16 decrypt [%d:%d:%d] error: %s\n", ik, ii, id, err)
					continue
				}

				if len(d) != len(decrypted) {
					t.Errorf("16 length [%d:%d:%d] need %d got %d\n", ik, ii, id, len(d), len(decrypted))
					continue
				}
				for k, v := range d {
					if v != decrypted[k] {
						t.Errorf("16 match [%d:%d:%d] need %d got %d\n", ik, ii, id, len(d), len(decrypted))
						break
					}
				}
			}
		}
	}
	for ik, k := range _testKey.Length24 {
		for ii, i := range _testIv {
			for id, d := range _testData {
				encrypted, err := AesCBCEncrypt(d, k, i)
				if err != nil {
					t.Errorf("24 encrypt [%d:%d:%d] error: %s\n", ik, ii, id, err)
					continue
				}
				decrypted, err := AesCBCDecrypt(encrypted, k, i)
				if err != nil {
					t.Errorf("24 decrypt [%d:%d:%d] error: %s\n", ik, ii, id, err)
					continue
				}
				if len(d) != len(decrypted) {
					t.Errorf("24 length [%d:%d:%d] need %d got %d\n", ik, ii, id, len(d), len(decrypted))
					continue
				}
				for k, v := range d {
					if v != decrypted[k] {
						t.Errorf("24 match [%d:%d:%d] need %d got %d\n", ik, ii, id, len(d), len(decrypted))
						break
					}
				}
			}
		}
	}
	for ik, k := range _testKey.Length32 {
		for ii, i := range _testIv {
			for id, d := range _testData {
				encrypted, err := AesCBCEncrypt(d, k, i)
				if err != nil {
					t.Errorf("32 encrypt [%d:%d:%d] error: %s\n", ik, ii, id, err)
					continue
				}
				decrypted, err := AesCBCDecrypt(encrypted, k, i)
				if err != nil {
					t.Errorf("32 decrypt [%d:%d:%d] error: %s\n", ik, ii, id, err)
					continue
				}
				if len(d) != len(decrypted) {
					t.Errorf("32 length [%d:%d:%d] need %d got %d\n", ik, ii, id, len(d), len(decrypted))
					continue
				}
				for k, v := range d {
					if v != decrypted[k] {
						t.Errorf("32 match [%d:%d:%d] need %d got %d\n", ik, ii, id, len(d), len(decrypted))
						break
					}
				}
			}
		}
	}
}

func ExampleAesCBCEncrypt() {
	enc, err := AesCBCEncrypt([]byte("hello"), []byte("1234567812345678"), []byte("1234567812345678"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x", enc)
	fmt.Printf("%s", hex.EncodeToString(enc))
}

func ExampleAesCBCDecrypt() {
	enc, _ := AesCBCEncrypt([]byte("hello"), []byte("1234567812345678"), []byte("1234567812345678"))

	dec, err := AesCBCDecrypt(enc, []byte("1234567812345678"), []byte("1234567812345678"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", dec)
}

func TestAesCTRFile(t *testing.T) {
	for _, v := range _testFile {
		err := AesCTREncryptFile(v, v+".enc", _testKey.Length32[4], _testIv[1])
		if err != nil {
			t.Error(err)
		}
		err = AesCTRDecryptFile(v+".enc", v+".dec", _testKey.Length32[4], _testIv[1])
		if err != nil {
			t.Error(err)
		}
	}
}

func ExampleAesCTREncryptFile() {
	err := AesCTREncryptFile("originFilename", "targetFilename", _testKey.Length32[4], _testIv[1])
	if err != nil {
		panic(err)
	}
}

func ExampleAesCTRDecryptFile() {
	err := AesCTRDecryptFile("originFilename", "targetFilename", _testKey.Length32[4], _testIv[1])
	if err != nil {
		panic(err)
	}
}

func TestAesCTRFileIO(t *testing.T) {
	bs := []byte{0xa1, 0x17, 0x00, 0x81}

	for _, v := range _testFile {
		// Encrypt
		inFile, err := os.Open(v)
		if err != nil {
			t.Error(err)
		}
		outFile, err := os.Create(v + ".enc")
		if err != nil {
			t.Error(err)
		}

		_, _ = outFile.Write(bs)

		err = AesCTREncryptFileIO(inFile, outFile, _testKey.Length32[4], _testIv[1])
		if err != nil {
			t.Error(err)
		}

		_ = inFile.Close()
		_ = outFile.Close()

		// Decrypt
		inFile, err = os.Open(v + ".enc")
		if err != nil {
			t.Error(err)
		}
		outFile, err = os.Create(v + ".dec")
		if err != nil {
			t.Error(err)
		}

		brs := make([]byte, len(bs))
		_, _ = io.ReadFull(inFile, brs)

		for k, v := range brs {
			if v != bs[k] {
				t.Errorf("mismatch bs and brs")
				break
			}
		}

		err = AesCTRDecryptFileIO(inFile, outFile, _testKey.Length32[4], _testIv[1])
		if err != nil {
			t.Error(err)
		}
	}
}

func ExampleAesCTREncryptFileIO() {
	inFile, _ := os.Open("originFilename")
	outFile, _ := os.Create("targetFilename")

	err := AesCTREncryptFileIO(inFile, outFile, _testKey.Length32[4], _testIv[1])
	if err != nil {
		panic(err)
	}
}

func ExampleAesCTRDecryptFileIO() {
	inFile, _ := os.Open("originFilename")
	outFile, _ := os.Create("targetFilename")

	err := AesCTRDecryptFileIO(inFile, outFile, _testKey.Length32[4], _testIv[1])
	if err != nil {
		panic(err)
	}
}
