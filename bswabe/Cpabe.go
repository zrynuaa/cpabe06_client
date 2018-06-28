package bswabe

import (
	"github.com/Doresimon/ABE/AES"
	"fmt"
)

func CP_Enc(pk *BswabePub, M string, p string) *BswabeCphKey {

	fmt.Println("----------Begin Enc----------")
	keyCph, key := Enc(pk,p)
	fmt.Println("Enc key: ", (key.Bytes())[0:32])

	m := []byte(M)
	ciphertext,_ := AES.AesEncrypt(m, (key.Bytes())[0:32])
	keyCph.ciphertext = ciphertext

	return keyCph
}

func CP_Dec(pk *BswabePub, sk *BswabePrv, keyCph *BswabeCphKey) []byte {

	fmt.Println("----------Begin Dec----------")
	beb := Dec(pk,sk,keyCph.Cph)
	if !beb.B {
		fmt.Println("Policy unmatched!\n")
		return nil
	}

	fmt.Println("Dec key: ", (beb.E.Bytes())[0:32])
	result,_ := AES.AesDecrypt(keyCph.ciphertext, (beb.E.Bytes())[0:32])
	return result
}