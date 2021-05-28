// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sm2 implements china crypto standards.
package sm2

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"github.com/cetcxinlian/cryptogm/sm3"
	"reflect"
	"testing"
)

type Assert struct {}

func (a *Assert)Equal(t *testing.T, expect, actual interface{}) {
	if reflect.TypeOf(expect) != reflect.TypeOf(actual) {
		t.Error("assert failed not equal", expect, actual)
		return
	}
	var buf1 bytes.Buffer
	enc1 := gob.NewEncoder(&buf1)
	enc1.Encode(expect)
	var buf2 bytes.Buffer
	enc2 := gob.NewEncoder(&buf2)
	enc2.Encode(expect)
	if bytes.Equal(buf1.Bytes(),buf2.Bytes()) {
		t.Log("true")
	} else {
		t.Error("assert failed not equal", expect, actual)
	}
}
func (a *Assert)True(t *testing.T, value bool) {
	if value == true {
		t.Log("true")
	} else {
		t.Error("assert failed %i is false", value)
	}
}
var assert Assert

func TestSignVerify(t *testing.T) {
	msg := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		panic("GenerateKey failed")
	}

	hfunc := sm3.New()
	hfunc.Write(msg)
	hash := hfunc.Sum(nil)

	r, s, err := Sign(rand.Reader, priv, hash)
	if err != nil {
		panic(err)
	}

	ret := Verify(&priv.PublicKey, hash, r, s)
	if !ret {
		t.Error("verify error")
	}
}

func TestKeyGeneration(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("error: %s", err)
		return
	}

	if !priv.PublicKey.Curve.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Errorf("public key invalid: %s", err)
	}
}

func BenchmarkSign(b *testing.B) {
	b.ResetTimer()
	origin := []byte("testing")
	hashed  := sm3.SumSM3(origin)
	priv, _ := GenerateKey(rand.Reader)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Sign(rand.Reader, priv, hashed[:])
	}
}

func TestSignAndVerify(t *testing.T) {
	priv, _ := GenerateKey(rand.Reader)

	origin := []byte("testintestintestintestintestintestinggggggtesting")
	hash := sm3.New()
	hash.Write(origin)
	hashed := hash.Sum(nil)
	r, s, err := Sign(rand.Reader, priv, hashed)
	if err != nil {
		t.Errorf(" error signing: %s", err)
		return
	}

	if !Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf(" Verify failed")
	}

	//hashed[0] ^= 0xff
	hashed[0] = 0x53
	for i := 0; i < len(hashed); i++ {
		hashed[i] = byte(i)
	}
	if Verify(&priv.PublicKey, hashed, r, s) {
		t.Errorf("Verify always works!")
	}
}