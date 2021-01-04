package encrypt

import "errors"

var (
	// ErrUnknown for undefined error
	ErrUnknown = errors.New("unknown error")
	// ErrCipherKey wrong key
	ErrCipherKey = errors.New("the secret key is wrong and cannot be decrypted. Please check")
	// ErrAESKeyLength wrong key length
	ErrAESKeyLength = errors.New("16 or 24 or 32 length secret key is required")
	// ErrPaddingSize padding size error
	ErrPaddingSize = errors.New("padding size error please check the secret key or iv")
	// ErrIvAes iv length error
	ErrIvAes = errors.New("a 16-length iv is required")
)
