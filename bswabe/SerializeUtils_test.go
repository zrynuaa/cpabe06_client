package bswabe

import (
	"github.com/zrynuaa/cpabe06/bswabe"
	"fmt"
	"testing"
)

func TestFunc(t *testing.T){
	pub := new(bswabe.BswabePub)
	msk := new(bswabe.BswabeMsk)
	bswabe.CP_Setup(pub,msk)

	data := bswabe.SerializeBswabePub(pub)
	ppuu := UnSerializeBswabePub(data) //获得服务端返回的公共参数

	//attrs1 := "foo fim baf"
	attrs1 := "foo fim "
	prv1 := bswabe.CP_Keygen(pub,msk,attrs1)
	data = bswabe.SerializeBswabePrv(prv1)
	pprr := UnSerializeBswabePrv(ppuu, data) //获取服务端返回的解密私钥


	policy := "foo bar fim 2of3 baf 1of2"
	M := "This is test message!"
	keyCph := CP_Enc(ppuu,M,policy) //本地加密

	data = SerializeBswabeCphKey(keyCph)
	keycph := UnSerializeBswabeCphKey(ppuu, data)


	result1 := CP_Dec(ppuu,pprr,keycph) //本地解密
	fmt.Println("\nresult1: " + string(result1))
}

