package main

import (
	"net/rpc"
	"log"
	"github.com/zrynuaa/cpabe06_client/bswabe"
	"fmt"
)

func main() {
	client, err := rpc.DialHTTP("tcp", "localhost:1234")
	if err != nil {
		log.Fatal("dialing:", err)
	}

	// Synchronous call同步方式调用
	var reply []byte
	err = client.Call("CPABE.Getpub", "", &reply)
	if err != nil {
		log.Fatal("arith error:", err)
	}
	pub := bswabe.UnSerializeBswabePub(reply)  //获取PublicKey

	attrs1 := "baf"
	err = client.Call("CPABE.Getsk", attrs1, &reply)
	if err != nil {
		log.Fatal("arith error:", err)
	}
	prv := bswabe.UnSerializeBswabePrv(pub, reply) //获取服务端返回的解密私钥

	policy := "foo bar fim 2of3 baf 1of2"
	M := "This is test message!"
	keyCph := bswabe.CP_Enc(pub,M,policy) //本地加密

	result := bswabe.CP_Dec(pub,prv,keyCph) //本地解密
	fmt.Println("\nresult: " + string(result))
}
