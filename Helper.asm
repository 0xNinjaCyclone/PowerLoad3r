
;****************************************
; Author  => Abdallah Mohamed
; Email   => elsharifabdallah53@gmail.com
; Date    => 4-3-2023/09:29PM
;****************************************


SSN_INITIAL EQU -1
INVALID_SSN EQU SSN_INITIAL


.data

; will store the syscall number to use with HellDescent procedure
wSysCallNumber DW ?


.code

; Get Process Environment Block
GetPEB proc
	; Read G Segment register which contains PEB and also TEB 
	mov rax, qword ptr gs:[60h]
	ret
GetPEB endp

; Get length of unicode string
; Input  = RDI -> Address of the string
; Output = RCX 
GetStrLenW proc
	push rax
	push rdi        ; save string pointer
	mov rcx, -1     ; biggest number possible
	xor ax, ax      ; NUL-Terminator
	repne scasw     ; repeat until reach NUL
	not rcx         ; convert to a positive number
	dec rcx         ; we started from -1
	pop rdi         ; restore string pointer
	pop rax
	ret
GetStrLenW endp

; Get length of ansi string
; Input  = RDI -> Address of the string
; Output = RCX 
GetStrLenA proc
	push rax
	push rdi        ; save string pointer
	mov rcx, -1     ; biggest number possible
	xor al, al      ; NUL-Terminator
	repne scasb     ; repeat until reach NUL
	not rcx         ; convert to a positive number
	dec rcx         ; we started from -1
	pop rdi         ; restore string pointer
	pop rax
	ret
GetStrLenA endp

; Compare unicode string 
; Input  = RSI -> Address of the src
;          RDI -> Address of the dest
;          RCX -> Number of the bytes 
; Output = ZF
StrNCmpW proc
	; Save inputs (The operation will destroy them)
	push rsi
	push rdi
	push rcx

	repe cmpsw
	
	; Restore inputs 
	pop rcx
	pop rdi
	pop rsi
	ret
StrNCmpW endp

; Compare ansi string 
; Input  = RSI -> Address of the src
;          RDI -> Address of the dest
;          RCX -> Number of bytes 
; Output = ZF
StrNCmpA proc
	; Save inputs (The operation will destroy them)
	push rsi
	push rdi
	push rcx

	repe cmpsb
	
	; Restore inputs 
	pop rcx
	pop rdi
	pop rsi
	ret
StrNCmpA endp

; Used in GetModuleHandle2 and GetProcAddress2
RequiredDataNotFound proc
	xor rax, rax          ; Return NULL if we didn't find the required data
	ret
RequiredDataNotFound endp

; Get Module Base Address 
GetModuleHandleW2 proc
	mov rdi, rcx              ; Module name
	call GetStrLenW           ; Get module name length
	call GetPEB               ; Get Process Environment Block 
	mov rax, [rax + 18h]      ; pPEB->pLdr
	lea rax, [rax + 20h]      ; &pLdr->InMemoryOrderModuleList
	                          ; We point to the first node in the list
	mov rbx, rax              ; Save first node address 
	
	NEXT_MODULE:
	cld                       ; Clear Direction Flag
	mov rax, [rax]            ; Move to the next node in the list 
	cmp rax, rbx              ; Check if we reach last node, first == last->next
	jz RequiredDataNotFound
	mov rsi, [rax + 50h]      ; Get unicode module name
	call StrNCmpW             ; Compare current dll name with required dll name
	jnz NEXT_MODULE           ; Search until find required module

	mov rax, [rax + 20h]      ; Get dll base address
	ret
GetModuleHandleW2 endp

; Get Procedure Address from a dll
GetProcAddress2 proc
	mov rdi, rdx                     ; Procedure name
	mov rdx, rcx                     ; Dll Base Address
	call GetStrLenA                  ; Get Length of required function name
	mov eax, dword ptr [rdx + 3Ch]   ; NT Headers RVA
	add rax, rdx                     ; DllBaseAddress + DOS->e_lfanew
	mov eax, dword ptr [rax + 88h]   ; Export Table RVA
	                                 ; IMAGE_NT_HEADERS->IMAGE_OPTIONAL_HEADER->IMAGE_DATA_DIRECTORY->VirtualAddress
	test rax, rax                    ; Check if no exports address
	jz RequiredDataNotFound

	add rax, rdx                     ; DllBaseAddress + ExportVirtualAddress
	push rcx                         ; Save procedure name length in the stack
	mov cx, word ptr [rax + 18h]     ; NumberOfNames
	mov r8d, dword ptr [rax + 20h]   ; AddressOfNames RVA
	add r8, rdx                      ; Add base address

	NEXT_FUNCTION:
	mov esi, [r8 + rcx * 4h]         ; Get procedure name RVA
	add rsi, rdx                     ; Add base address
	pop rbx                          ; Restore procedure name length from the stack
	xchg rbx, rcx                    ; Toggling between prcedure name and number of functions
	call StrNCmpA                    ; Compare current function name with required function name
	jz FOUND                         ; Jump if we found the required function 
	xchg rbx, rcx                    ; Back function length and number of function names again
	push rbx                         ; Save function name length in the stack
	loop NEXT_FUNCTION

	; Required function doesn't exist in this dll
	pop rbx
	jmp RequiredDataNotFound

	FOUND:
	; Check if the length of the found function equal required function length
	xchg rsi, rdi                    ; Toggling between current function name and required function name
	                                 ; because GetStrLenA takes rdi as a parameter
	xchg rbx, rcx                    ; Toggling between prcedure name and number of functions
	push rbx                         ; Save required function name length
	push rcx                         ; Save number of function names
	call GetStrLenA                  ; Get length of current function name
	cmp rcx, rbx                     ; CurrentFunctionLength == RequiredFunctionLength ?
	pop rcx                          ; Restore number of function names
	xchg rsi, rdi                    ; back them again
	jnz NEXT_FUNCTION2               ; If length of both not same we should dig deeper
	                                 ; Maybe we were comparing some thing like VirtualAlloc and VirtualAllocEx
	                                 ; We had better avoid this cases

	pop rbx
	mov r9d, dword ptr [rax + 24h]   ; AddressOfNameOrdinals RVA
	add r9, rdx                      ; Add base address
	mov cx, word ptr [r9 + 2h * rcx] ; Get required function ordinal
	mov r8d, dword ptr [rax + 1Ch]   ; AddressOfFunctions RVA
	add r8, rdx                      ; Add base address
	mov eax, [r8 + 4h * rcx]         ; Get required function address RVA
	add rax, rdx                     ; Add base address
	ret

	NEXT_FUNCTION2:
	dec rcx                          ; Decrease loop counter 
	jmp NEXT_FUNCTION                ; Dig deeper

GetProcAddress2 endp

; For return -1 if the syscall was hooked
InvalidSyscall proc
	mov rax, INVALID_SSN
	ret
InvalidSyscall endp

; Grab syscall number dynamically
HellsGateGrabber proc
	;**********************************************************************
	;	every syscall starts with the following instrucions
	;	    - mov r10, rcx
	;	    - mov eax, <SyscallNumber> <-- We need to resolve this number
	;**********************************************************************

	
	mov esi, 0b8d18b4ch   ; syscall pattern
	mov edi, [rcx]        ; move the syscall content into edi 
	cmp esi, edi          ; Check if hooked or not
	jne InvalidSyscall    ; return -1 if hooked
	xor rax, rax          ; Clear accumlator 
	mov ax, [rcx + 4]     ; Grab the syscall number
	ret
HellsGateGrabber endp

; Prepare the syscall
HellsGate proc
	; Read syscall number as a parameter and store it in the memory
	mov wSysCallNumber, cx
	ret
HellsGate endp

; Call the specified syscall
HellDescent proc
	mov r10, rcx
	mov eax, dword ptr wSysCallNumber
	syscall
	ret
HellDescent endp

; Try to resolve syscall from neighbors
HaloGateDown proc
	mov rax, 20h         ; Stub size
	xor rbx, rbx         ; Clear rbx register
	mov bx, dx           ; Save dx in bx to use it later, because mul instruction will destroy dx
	mul dx               ; Multiply size of syscall by the index of neighbors
	add rcx, rax         ; Go down
	mov edi, [rcx]       ; Move the neighbor syscall content into edi 
	mov esi, 0b8d18b4ch  ; Native API instructions pattern
	cmp esi, edi         ; Check if the given NTAPI Address matches the pattern
	jne InvalidSyscall   ; If hooked return -1

	; Return the syscall number
	xor rax, rax
	mov ax, [rcx + 4]
	sub ax, bx
	ret
HaloGateDown endp

; Try to resolve syscall from neighbors
HaloGateUp proc
	mov rax, 20h 
	xor rbx, rbx 
	mov bx, dx
	mul dx
	sub rcx, rax     ; Go up
	mov edi, [rcx]
	mov esi, 0b8d18b4ch
	cmp esi, edi
	jne InvalidSyscall

	xor rax, rax
	mov ax, [rcx + 4]
	add ax, bx
	ret
HaloGateUp endp

; Used in VelesReek
FixSyscallNumber proc
	inc rax
	ret
FixSyscallNumber endp

; Calculate syscall number from its position between others syscalls
VelesReek proc
	mov rbx, SSN_INITIAL
	mov edi, 0cdc3050fh  ; Pattern of -> 'syscall ; ret ; int'

	DIG:
	mov esi, [rdx]       ; Move instructions into esi to campare with the pattern
	cmp esi, edi         ; Compare pattern with current instructions
	je SYSCALL_FOUND
	
	NEXT:
	inc rdx              ; Move to the next address
	loop DIG             ; Dig deeper

	; To avoid the unexpected behavior if the given module address was not the expected 
	jmp InvalidSyscall
	
	SYSCALL_FOUND:
	inc rbx              ; Increase SSN counter
	lea rax, [rdx - 12h] ; Stub address
	cmp rax, r8          ; Check if it's the target stub or not, to continue in digging
	jne NEXT             ; If it's not the target syscall, dig deeper
	mov rax, rbx         ; For return syscall number
	mov cx, 05ah         ; NtQuerySystemTime syscall number
	cmp bx, cx           ; check if the syscall number we found after NtQuerySystemTime or not

	; If the syscall number we found is greater than NtQuerySystemTime number, we must increase it by one
	; because we missed this syscall, because it doesn't have the pattern we use.
	jge FixSyscallNumber

	ret
VelesReek endp
	
end