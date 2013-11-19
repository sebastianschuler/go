// Inferno's libkern/memmove-386.s
// http://code.google.com/p/inferno-os/source/browse/libkern/memmove-386.s
//
//         Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//         Revisions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com).  All rights reserved.
//         Portions Copyright 2009 The Go Authors. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

TEXT runtime·memmove(SB), 7, $0
	MOVL	to+0(FP), DI
	MOVL	fr+4(FP), SI
	MOVL	n+8(FP), BX
/*
 * check and set for backwards
 */
	CMPL	SI, DI
	JLS	back

/*
 * forward copy loop
 */
forward:	
	MOVL	BX, CX
	SHRL	$2, CX
	ANDL	$3, BX

	REP;	MOVSL
	MOVL	BX, CX
	REP;	MOVSB

	MOVL	to+0(FP),AX
	RET
/*
 * check overlap
 */
back:
	MOVL	SI, CX
	ADDL	BX, CX
	CMPL	CX, DI
	JLS	forward
/*
 * whole thing backwards has
 * adjusted addresses
 */

	ADDL	BX, DI
	ADDL	BX, SI
	STD

/*
 * copy
 */
	MOVL	BX, CX
	SHRL	$2, CX
	ANDL	$3, BX

	SUBL	$4, DI
	SUBL	$4, SI
	REP;	MOVSL

	ADDL	$3, DI
	ADDL	$3, SI
	MOVL	BX, CX
	REP;	MOVSB

	CLD
	MOVL	to+0(FP),AX
	RET

