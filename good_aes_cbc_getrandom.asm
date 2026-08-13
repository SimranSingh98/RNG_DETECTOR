	.def	@feat.00;
	.scl	3;
	.type	0;
	.endef
	.globl	@feat.00
@feat.00 = 0
	.intel_syntax noprefix
	.file	"good_aes_cbc_getrandom.c"
	.def	sprintf;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,sprintf
	.globl	sprintf                         # -- Begin function sprintf
	.p2align	4
sprintf:                                # @sprintf
.seh_proc sprintf
# %bb.0:
	sub	rsp, 72
	.seh_stackalloc 72
	.seh_endprologue
	mov	qword ptr [rsp + 104], r9
	mov	qword ptr [rsp + 96], r8
	mov	rax, qword ptr [rip + __security_cookie]
	xor	rax, rsp
	mov	qword ptr [rsp + 64], rax
	mov	qword ptr [rsp + 48], rdx
	mov	qword ptr [rsp + 40], rcx
	lea	rax, [rsp + 96]
	mov	qword ptr [rsp + 56], rax
	mov	r9, qword ptr [rsp + 56]
	mov	rdx, qword ptr [rsp + 48]
	mov	rcx, qword ptr [rsp + 40]
	xor	eax, eax
	mov	r8d, eax
	call	_vsprintf_l
	mov	dword ptr [rsp + 36], eax
	mov	eax, dword ptr [rsp + 36]
	mov	dword ptr [rsp + 32], eax       # 4-byte Spill
	mov	rcx, qword ptr [rsp + 64]
	xor	rcx, rsp
	mov	rax, qword ptr [rip + __security_cookie]
	sub	rax, rcx
	jne	.LBB0_2
	jmp	.LBB0_1
.LBB0_2:
	mov	rcx, qword ptr [rsp + 64]
	xor	rcx, rsp
	call	__security_check_cookie
.LBB0_1:
	mov	eax, dword ptr [rsp + 32]       # 4-byte Reload
	.seh_startepilogue
	add	rsp, 72
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	vsprintf;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,vsprintf
	.globl	vsprintf                        # -- Begin function vsprintf
	.p2align	4
vsprintf:                               # @vsprintf
.seh_proc vsprintf
# %bb.0:
	sub	rsp, 72
	.seh_stackalloc 72
	.seh_endprologue
	mov	qword ptr [rsp + 64], r8
	mov	qword ptr [rsp + 56], rdx
	mov	qword ptr [rsp + 48], rcx
	mov	rax, qword ptr [rsp + 64]
	mov	r8, qword ptr [rsp + 56]
	mov	rcx, qword ptr [rsp + 48]
	mov	rdx, -1
	xor	r9d, r9d
                                        # kill: def $r9 killed $r9d
	mov	qword ptr [rsp + 32], rax
	call	_vsnprintf_l
	nop
	.seh_startepilogue
	add	rsp, 72
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	_snprintf;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,_snprintf
	.globl	_snprintf                       # -- Begin function _snprintf
	.p2align	4
_snprintf:                              # @_snprintf
.seh_proc _snprintf
# %bb.0:
	sub	rsp, 88
	.seh_stackalloc 88
	.seh_endprologue
	mov	qword ptr [rsp + 120], r9
	mov	rax, qword ptr [rip + __security_cookie]
	xor	rax, rsp
	mov	qword ptr [rsp + 80], rax
	mov	qword ptr [rsp + 64], r8
	mov	qword ptr [rsp + 56], rdx
	mov	qword ptr [rsp + 48], rcx
	lea	rax, [rsp + 120]
	mov	qword ptr [rsp + 72], rax
	mov	r9, qword ptr [rsp + 72]
	mov	r8, qword ptr [rsp + 64]
	mov	rdx, qword ptr [rsp + 56]
	mov	rcx, qword ptr [rsp + 48]
	call	_vsnprintf
	mov	dword ptr [rsp + 44], eax
	mov	eax, dword ptr [rsp + 44]
	mov	dword ptr [rsp + 40], eax       # 4-byte Spill
	mov	rcx, qword ptr [rsp + 80]
	xor	rcx, rsp
	mov	rax, qword ptr [rip + __security_cookie]
	sub	rax, rcx
	jne	.LBB2_2
	jmp	.LBB2_1
.LBB2_2:
	mov	rcx, qword ptr [rsp + 80]
	xor	rcx, rsp
	call	__security_check_cookie
.LBB2_1:
	mov	eax, dword ptr [rsp + 40]       # 4-byte Reload
	.seh_startepilogue
	add	rsp, 88
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	_vsnprintf;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,_vsnprintf
	.globl	_vsnprintf                      # -- Begin function _vsnprintf
	.p2align	4
_vsnprintf:                             # @_vsnprintf
.seh_proc _vsnprintf
# %bb.0:
	sub	rsp, 72
	.seh_stackalloc 72
	.seh_endprologue
	mov	qword ptr [rsp + 64], r9
	mov	qword ptr [rsp + 56], r8
	mov	qword ptr [rsp + 48], rdx
	mov	qword ptr [rsp + 40], rcx
	mov	rax, qword ptr [rsp + 64]
	mov	r8, qword ptr [rsp + 56]
	mov	rdx, qword ptr [rsp + 48]
	mov	rcx, qword ptr [rsp + 40]
	xor	r9d, r9d
                                        # kill: def $r9 killed $r9d
	mov	qword ptr [rsp + 32], rax
	call	_vsnprintf_l
	nop
	.seh_startepilogue
	add	rsp, 72
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	generate_iv;
	.scl	2;
	.type	32;
	.endef
	.text
	.globl	generate_iv                     # -- Begin function generate_iv
	.p2align	4
generate_iv:                            # @generate_iv
.seh_proc generate_iv
# %bb.0:
	sub	rsp, 56
	.seh_stackalloc 56
	.seh_endprologue
	mov	qword ptr [rsp + 40], rcx
	mov	rdx, qword ptr [rsp + 40]
	xor	eax, eax
	mov	ecx, eax
	mov	r8d, 16
	mov	r9d, 2
	call	BCryptGenRandom
	mov	dword ptr [rsp + 36], eax
	cmp	dword ptr [rsp + 36], 0
	je	.LBB4_2
# %bb.1:
	mov	dword ptr [rsp + 52], -1
	jmp	.LBB4_3
.LBB4_2:
	mov	dword ptr [rsp + 52], 0
.LBB4_3:
	mov	eax, dword ptr [rsp + 52]
	.seh_startepilogue
	add	rsp, 56
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	aes_cbc_encrypt;
	.scl	2;
	.type	32;
	.endef
	.globl	aes_cbc_encrypt                 # -- Begin function aes_cbc_encrypt
	.p2align	4
aes_cbc_encrypt:                        # @aes_cbc_encrypt
.seh_proc aes_cbc_encrypt
# %bb.0:
	sub	rsp, 72
	.seh_stackalloc 72
	.seh_endprologue
	mov	rax, qword ptr [rsp + 112]
	mov	qword ptr [rsp + 64], r9
	mov	qword ptr [rsp + 56], r8
	mov	qword ptr [rsp + 48], rdx
	mov	qword ptr [rsp + 40], rcx
	lea	rcx, [rip + "??_C@_0BN@JEMCMDGJ@AES?9CBC?5operation?5completed?6?$AA@"]
	call	printf
	nop
	.seh_startepilogue
	add	rsp, 72
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	printf;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,printf
	.globl	printf                          # -- Begin function printf
	.p2align	4
printf:                                 # @printf
.seh_proc printf
# %bb.0:
	sub	rsp, 88
	.seh_stackalloc 88
	.seh_endprologue
	mov	qword ptr [rsp + 120], r9
	mov	qword ptr [rsp + 112], r8
	mov	qword ptr [rsp + 104], rdx
	mov	rax, qword ptr [rip + __security_cookie]
	xor	rax, rsp
	mov	qword ptr [rsp + 80], rax
	mov	qword ptr [rsp + 64], rcx
	lea	rax, [rsp + 104]
	mov	qword ptr [rsp + 72], rax
	mov	rax, qword ptr [rsp + 72]
	mov	qword ptr [rsp + 48], rax       # 8-byte Spill
	mov	rax, qword ptr [rsp + 64]
	mov	qword ptr [rsp + 40], rax       # 8-byte Spill
	mov	ecx, 1
	call	__acrt_iob_func
	mov	rdx, qword ptr [rsp + 40]       # 8-byte Reload
	mov	r9, qword ptr [rsp + 48]        # 8-byte Reload
	mov	rcx, rax
	xor	eax, eax
	mov	r8d, eax
	call	_vfprintf_l
	mov	dword ptr [rsp + 60], eax
	mov	eax, dword ptr [rsp + 60]
	mov	dword ptr [rsp + 56], eax       # 4-byte Spill
	mov	rcx, qword ptr [rsp + 80]
	xor	rcx, rsp
	mov	rax, qword ptr [rip + __security_cookie]
	sub	rax, rcx
	jne	.LBB6_2
	jmp	.LBB6_1
.LBB6_2:
	mov	rcx, qword ptr [rsp + 80]
	xor	rcx, rsp
	call	__security_check_cookie
.LBB6_1:
	mov	eax, dword ptr [rsp + 56]       # 4-byte Reload
	.seh_startepilogue
	add	rsp, 88
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	main;
	.scl	2;
	.type	32;
	.endef
	.text
	.globl	main                            # -- Begin function main
	.p2align	4
main:                                   # @main
.seh_proc main
# %bb.0:
	sub	rsp, 120
	.seh_stackalloc 120
	.seh_endprologue
	mov	rax, qword ptr [rip + __security_cookie]
	xor	rax, rsp
	mov	qword ptr [rsp + 112], rax
	mov	dword ptr [rsp + 44], 0
	mov	rax, qword ptr [rip + .L__const.main.key]
	mov	qword ptr [rsp + 96], rax
	mov	rax, qword ptr [rip + .L__const.main.key+8]
	mov	qword ptr [rsp + 104], rax
	mov	rax, qword ptr [rip + .L__const.main.plaintext]
	mov	qword ptr [rsp + 64], rax
	mov	rax, qword ptr [rip + .L__const.main.plaintext+8]
	mov	qword ptr [rsp + 72], rax
	lea	rcx, [rsp + 48]
	xor	edx, edx
	mov	r8d, 16
	call	memset
	lea	rcx, [rsp + 80]
	call	generate_iv
	cmp	eax, 0
	je	.LBB7_2
# %bb.1:
	mov	ecx, 2
	call	__acrt_iob_func
	mov	rcx, rax
	lea	rdx, [rip + "??_C@_0BH@JDMCGHJI@Failed?5to?5generate?5IV?6?$AA@"]
	call	fprintf
	mov	dword ptr [rsp + 44], 1
	jmp	.LBB7_3
.LBB7_2:
	lea	r9, [rsp + 48]
	lea	r8, [rsp + 64]
	lea	rdx, [rsp + 80]
	lea	rcx, [rsp + 96]
	mov	qword ptr [rsp + 32], 16
	call	aes_cbc_encrypt
	mov	dword ptr [rsp + 44], 0
.LBB7_3:
	mov	eax, dword ptr [rsp + 44]
	mov	dword ptr [rsp + 40], eax       # 4-byte Spill
	mov	rcx, qword ptr [rsp + 112]
	xor	rcx, rsp
	mov	rax, qword ptr [rip + __security_cookie]
	sub	rax, rcx
	jne	.LBB7_5
	jmp	.LBB7_4
.LBB7_5:
	mov	rcx, qword ptr [rsp + 112]
	xor	rcx, rsp
	call	__security_check_cookie
.LBB7_4:
	mov	eax, dword ptr [rsp + 40]       # 4-byte Reload
	.seh_startepilogue
	add	rsp, 120
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	fprintf;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,fprintf
	.globl	fprintf                         # -- Begin function fprintf
	.p2align	4
fprintf:                                # @fprintf
.seh_proc fprintf
# %bb.0:
	sub	rsp, 72
	.seh_stackalloc 72
	.seh_endprologue
	mov	qword ptr [rsp + 104], r9
	mov	qword ptr [rsp + 96], r8
	mov	rax, qword ptr [rip + __security_cookie]
	xor	rax, rsp
	mov	qword ptr [rsp + 64], rax
	mov	qword ptr [rsp + 48], rdx
	mov	qword ptr [rsp + 40], rcx
	lea	rax, [rsp + 96]
	mov	qword ptr [rsp + 56], rax
	mov	r9, qword ptr [rsp + 56]
	mov	rdx, qword ptr [rsp + 48]
	mov	rcx, qword ptr [rsp + 40]
	xor	eax, eax
	mov	r8d, eax
	call	_vfprintf_l
	mov	dword ptr [rsp + 36], eax
	mov	eax, dword ptr [rsp + 36]
	mov	dword ptr [rsp + 32], eax       # 4-byte Spill
	mov	rcx, qword ptr [rsp + 64]
	xor	rcx, rsp
	mov	rax, qword ptr [rip + __security_cookie]
	sub	rax, rcx
	jne	.LBB8_2
	jmp	.LBB8_1
.LBB8_2:
	mov	rcx, qword ptr [rsp + 64]
	xor	rcx, rsp
	call	__security_check_cookie
.LBB8_1:
	mov	eax, dword ptr [rsp + 32]       # 4-byte Reload
	.seh_startepilogue
	add	rsp, 72
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	_vsprintf_l;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,_vsprintf_l
	.globl	_vsprintf_l                     # -- Begin function _vsprintf_l
	.p2align	4
_vsprintf_l:                            # @_vsprintf_l
.seh_proc _vsprintf_l
# %bb.0:
	sub	rsp, 72
	.seh_stackalloc 72
	.seh_endprologue
	mov	qword ptr [rsp + 64], r9
	mov	qword ptr [rsp + 56], r8
	mov	qword ptr [rsp + 48], rdx
	mov	qword ptr [rsp + 40], rcx
	mov	rax, qword ptr [rsp + 64]
	mov	r9, qword ptr [rsp + 56]
	mov	r8, qword ptr [rsp + 48]
	mov	rcx, qword ptr [rsp + 40]
	mov	rdx, -1
	mov	qword ptr [rsp + 32], rax
	call	_vsnprintf_l
	nop
	.seh_startepilogue
	add	rsp, 72
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	_vsnprintf_l;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,_vsnprintf_l
	.globl	_vsnprintf_l                    # -- Begin function _vsnprintf_l
	.p2align	4
_vsnprintf_l:                           # @_vsnprintf_l
.seh_proc _vsnprintf_l
# %bb.0:
	sub	rsp, 136
	.seh_stackalloc 136
	.seh_endprologue
	mov	rax, qword ptr [rsp + 176]
	mov	qword ptr [rsp + 128], r9
	mov	qword ptr [rsp + 120], r8
	mov	qword ptr [rsp + 112], rdx
	mov	qword ptr [rsp + 104], rcx
	mov	rax, qword ptr [rsp + 176]
	mov	qword ptr [rsp + 88], rax       # 8-byte Spill
	mov	rax, qword ptr [rsp + 128]
	mov	qword ptr [rsp + 80], rax       # 8-byte Spill
	mov	rax, qword ptr [rsp + 120]
	mov	qword ptr [rsp + 72], rax       # 8-byte Spill
	mov	rax, qword ptr [rsp + 112]
	mov	qword ptr [rsp + 64], rax       # 8-byte Spill
	mov	rax, qword ptr [rsp + 104]
	mov	qword ptr [rsp + 56], rax       # 8-byte Spill
	call	__local_stdio_printf_options
	mov	rdx, qword ptr [rsp + 56]       # 8-byte Reload
	mov	r8, qword ptr [rsp + 64]        # 8-byte Reload
	mov	r9, qword ptr [rsp + 72]        # 8-byte Reload
	mov	r10, qword ptr [rsp + 80]       # 8-byte Reload
	mov	rcx, rax
	mov	rax, qword ptr [rsp + 88]       # 8-byte Reload
	mov	rcx, qword ptr [rcx]
	or	rcx, 1
	mov	qword ptr [rsp + 32], r10
	mov	qword ptr [rsp + 40], rax
	call	__stdio_common_vsprintf
	mov	dword ptr [rsp + 100], eax
	cmp	dword ptr [rsp + 100], 0
	jge	.LBB10_2
# %bb.1:
	mov	eax, 4294967295
	mov	dword ptr [rsp + 52], eax       # 4-byte Spill
	jmp	.LBB10_3
.LBB10_2:
	mov	eax, dword ptr [rsp + 100]
	mov	dword ptr [rsp + 52], eax       # 4-byte Spill
.LBB10_3:
	mov	eax, dword ptr [rsp + 52]       # 4-byte Reload
	.seh_startepilogue
	add	rsp, 136
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.def	__local_stdio_printf_options;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,__local_stdio_printf_options
	.globl	__local_stdio_printf_options    # -- Begin function __local_stdio_printf_options
	.p2align	4
__local_stdio_printf_options:           # @__local_stdio_printf_options
# %bb.0:
	lea	rax, [rip + __local_stdio_printf_options._OptionsStorage]
	ret
                                        # -- End function
	.def	_vfprintf_l;
	.scl	2;
	.type	32;
	.endef
	.section	.text,"xr",discard,_vfprintf_l
	.globl	_vfprintf_l                     # -- Begin function _vfprintf_l
	.p2align	4
_vfprintf_l:                            # @_vfprintf_l
.seh_proc _vfprintf_l
# %bb.0:
	sub	rsp, 104
	.seh_stackalloc 104
	.seh_endprologue
	mov	qword ptr [rsp + 96], r9
	mov	qword ptr [rsp + 88], r8
	mov	qword ptr [rsp + 80], rdx
	mov	qword ptr [rsp + 72], rcx
	mov	rax, qword ptr [rsp + 96]
	mov	qword ptr [rsp + 64], rax       # 8-byte Spill
	mov	rax, qword ptr [rsp + 88]
	mov	qword ptr [rsp + 56], rax       # 8-byte Spill
	mov	rax, qword ptr [rsp + 80]
	mov	qword ptr [rsp + 48], rax       # 8-byte Spill
	mov	rax, qword ptr [rsp + 72]
	mov	qword ptr [rsp + 40], rax       # 8-byte Spill
	call	__local_stdio_printf_options
	mov	rdx, qword ptr [rsp + 40]       # 8-byte Reload
	mov	r8, qword ptr [rsp + 48]        # 8-byte Reload
	mov	r9, qword ptr [rsp + 56]        # 8-byte Reload
	mov	rcx, rax
	mov	rax, qword ptr [rsp + 64]       # 8-byte Reload
	mov	rcx, qword ptr [rcx]
	mov	qword ptr [rsp + 32], rax
	call	__stdio_common_vfprintf
	nop
	.seh_startepilogue
	add	rsp, 104
	.seh_endepilogue
	ret
	.seh_endproc
                                        # -- End function
	.section	.rdata,"dr",discard,"??_C@_0BN@JEMCMDGJ@AES?9CBC?5operation?5completed?6?$AA@"
	.globl	"??_C@_0BN@JEMCMDGJ@AES?9CBC?5operation?5completed?6?$AA@" # @"??_C@_0BN@JEMCMDGJ@AES?9CBC?5operation?5completed?6?$AA@"
"??_C@_0BN@JEMCMDGJ@AES?9CBC?5operation?5completed?6?$AA@":
	.asciz	"AES-CBC operation completed\n"

	.section	.rdata,"dr"
	.p2align	4, 0x0                          # @__const.main.key
.L__const.main.key:
	.ascii	"\000\001\002\003\004\005\006\007\b\t\n\013\f\r\016\017"

	.p2align	4, 0x0                          # @__const.main.plaintext
.L__const.main.plaintext:
	.ascii	"Hello Crypto!!!!"

	.section	.rdata,"dr",discard,"??_C@_0BH@JDMCGHJI@Failed?5to?5generate?5IV?6?$AA@"
	.globl	"??_C@_0BH@JDMCGHJI@Failed?5to?5generate?5IV?6?$AA@" # @"??_C@_0BH@JDMCGHJI@Failed?5to?5generate?5IV?6?$AA@"
"??_C@_0BH@JDMCGHJI@Failed?5to?5generate?5IV?6?$AA@":
	.asciz	"Failed to generate IV\n"

	.lcomm	__local_stdio_printf_options._OptionsStorage,8,8 # @__local_stdio_printf_options._OptionsStorage
	.section	.drectve,"yni"
	.ascii	" /DEFAULTLIB:libcmt.lib"
	.ascii	" /DEFAULTLIB:oldnames.lib"
	.ascii	" /DEFAULTLIB:uuid.lib"
	.ascii	" /DEFAULTLIB:uuid.lib"
	.ascii	" /DEFAULTLIB:bcrypt.lib"
	.section	.debug$S,"dr"
	.p2align	2, 0x0
	.long	4                               # Debug section magic
	.long	241
	.long	.Ltmp1-.Ltmp0                   # Subsection size
.Ltmp0:
	.short	.Ltmp3-.Ltmp2                   # Record length
.Ltmp2:
	.short	4353                            # Record kind: S_OBJNAME
	.long	0                               # Signature
	.byte	0                               # Object name
	.p2align	2, 0x0
.Ltmp3:
	.short	.Ltmp5-.Ltmp4                   # Record length
.Ltmp4:
	.short	4412                            # Record kind: S_COMPILE3
	.long	0                               # Flags and language
	.short	208                             # CPUType
	.short	22                              # Frontend version
	.short	1
	.short	6
	.short	0
	.short	22016                           # Backend version
	.short	0
	.short	0
	.short	0
	.asciz	"clang version 22.1.6 (https://github.com/llvm/llvm-project fc4aad7b5db3fff421df9a9637605b9ca5667881)" # Null-terminated compiler version string
	.p2align	2, 0x0
.Ltmp5:
.Ltmp1:
	.p2align	2, 0x0
	.addrsig
	.addrsig_sym _vsnprintf
	.addrsig_sym generate_iv
	.addrsig_sym BCryptGenRandom
	.addrsig_sym aes_cbc_encrypt
	.addrsig_sym printf
	.addrsig_sym fprintf
	.addrsig_sym __acrt_iob_func
	.addrsig_sym _vsprintf_l
	.addrsig_sym _vsnprintf_l
	.addrsig_sym __stdio_common_vsprintf
	.addrsig_sym __local_stdio_printf_options
	.addrsig_sym _vfprintf_l
	.addrsig_sym __stdio_common_vfprintf
	.addrsig_sym __local_stdio_printf_options._OptionsStorage
