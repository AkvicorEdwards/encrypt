package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
	"runtime"
)

// AesCBCEncrypt encrypt data use AES/CBC/PKCS5
//
// key: 16 or 24 or 32 length secret key is required
//
// iv : 16 length iv is required
func AesCBCEncrypt(plainText, key, iv []byte) (cipherText []byte, err error) {
	blockMode, err := CBCBlockMode(key, iv, true)
	if err != nil {
		return nil, err
	}
	paddingText := PKCS5Padding(plainText, blockMode.BlockSize())
	cipherText = make([]byte, len(paddingText))
	blockMode.CryptBlocks(cipherText, paddingText)
	return cipherText, nil
}

// AesCBCDecrypt decrypt data use AES/CBC/PKCS5
//
// key: 16 or 24 or 32 length secret key is required
//
// iv : 16 length iv is required
func AesCBCDecrypt(cipherText, key, iv []byte) (plainText []byte, err error) {
	defer func() {
		if er := recover(); er != nil {
			switch er.(type) {
			case runtime.Error:
				err = ErrCipherKey
			default:
				err = ErrUnknown
			}
		}
	}()

	blockMode, err := CBCBlockMode(key, iv, false)
	if err != nil {
		return nil, err
	}

	paddingText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(paddingText, cipherText)
	plainText, err = PKCS5UnPadding(paddingText)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

// AesCTREncryptFile encrypt file use AES/CTR
//
// key: 16 or 24 or 32 length secret key is required
//
// iv : 16 length iv is required
func AesCTREncryptFile(origin, target string, key, iv []byte) (err error) {
	stream, err := CTRStream(key, iv)
	if err != nil {
		return err
	}

	inFile, err := os.Open(origin)
	if err != nil {
		return err
	}
	defer func() {
		_ = inFile.Close()
	}()

	outFile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer func() {
		_ = outFile.Close()
	}()

	writer := &cipher.StreamWriter{S: stream, W: outFile}
	defer func() {
		_ = writer.Close()
	}()

	_, err = io.Copy(writer, inFile)
	if err != nil {
		return err
	}

	return nil
}

// AesCTRDecryptFile decrypt file use AES/CTR
//
// key: 16 or 24 or 32 length secret key is required
//
// iv : 16 length iv is required
func AesCTRDecryptFile(origin, target string, key, iv []byte) (err error) {
	defer func() {
		if er := recover(); er != nil {
			switch er.(type) {
			case runtime.Error:
				err = ErrCipherKey
			default:
				err = ErrUnknown
			}
		}
	}()

	stream, err := CTRStream(key, iv)
	if err != nil {
		return err
	}

	inFile, err := os.Open(origin)
	if err != nil {
		return err
	}
	defer func() {
		_ = inFile.Close()
	}()

	outFile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer func() {
		_ = outFile.Close()
	}()

	reader := &cipher.StreamReader{S: stream, R: inFile}

	_, err = io.Copy(outFile, reader)
	if err != nil {
		return err
	}

	return nil
}

// AesCTREncryptFileIO encrypt file use AES/CTR
//
// key: 16 or 24 or 32 length secret key is required
//
// iv : 16 length iv is required
func AesCTREncryptFileIO(origin, target *os.File, key, iv []byte) (err error) {
	stream, err := CTRStream(key, iv)
	if err != nil {
		return err
	}

	writer := &cipher.StreamWriter{S: stream, W: target}
	defer func() {
		_ = writer.Close()
	}()

	_, err = io.Copy(writer, origin)
	if err != nil {
		return err
	}

	return nil
}

// AesCTRDecryptFileIO decrypt file use AES/CTR
//
// key: 16 or 24 or 32 length secret key is required
//
// iv : 16 length iv is required
func AesCTRDecryptFileIO(origin, target *os.File, key, iv []byte) (err error) {
	defer func() {
		if er := recover(); er != nil {
			switch er.(type) {
			case runtime.Error:
				err = ErrCipherKey
			default:
				err = ErrUnknown
			}
		}
	}()

	stream, err := CTRStream(key, iv)
	if err != nil {
		return err
	}

	reader := &cipher.StreamReader{S: stream, R: origin}

	_, err = io.Copy(target, reader)
	if err != nil {
		return err
	}

	return nil
}

// CTRStream create a CTR cipher.Stream use key and iv
//
// key: 16 or 24 or 32 length secret key is required
//
// iv : 16 length iv is required
func CTRStream(key, iv []byte) (cipher.Stream, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrAESKeyLength
	}
	if len(iv) == 0 {
		iv = []byte(defaultAesIv)
	}
	if len(iv) != aes.BlockSize {
		return nil, ErrIvAes
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// CBCBlockMode create a CBC cipher.BlockMode use key and iv
//
// key: 16 or 24 or 32 length secret key is required
//
// iv : 16 length iv is required
//
// encrypt: if true return a encrypt cipher.BlockMode. else return a decrypt cipher.BlockMode
func CBCBlockMode(key, iv []byte, encrypt bool) (cipher.BlockMode, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, ErrAESKeyLength
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(iv) == 0 {
		iv = []byte(defaultAesIv)
	}
	if len(iv) != 16 {
		return nil, ErrIvAes
	}

	if encrypt {
		return cipher.NewCBCEncrypter(block, iv), nil
	}

	return cipher.NewCBCDecrypter(block, iv), nil
}
