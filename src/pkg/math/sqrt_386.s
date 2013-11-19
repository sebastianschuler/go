// Copyright 2009 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// func Sqrt(x float64) float64	
TEXT ·Sqrt(SB),7,$0
	FMOVD   x+0(FP),F0
	FSQRT
	FMOVDP  F0,ret+8(FP)
	RET
