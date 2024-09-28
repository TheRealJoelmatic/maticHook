; NtProtectVirtualMemory.asm
; Assembly implementation of NtProtectVirtualMemory syscall.

; Disable automatic prologue/epilogue generation
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE

.code

; Export the function
PUBLIC MyNtProtectVirtualMemory

; Define the function
MyNtProtectVirtualMemory PROC
    ; Parameters are passed in:
    ; rcx: HANDLE ProcessHandle
    ; rdx: PVOID* BaseAddress
    ; r8:  PSIZE_T RegionSize
    ; r9:  ULONG NewProtect
    ; [rsp+8]: PULONG OldProtect

    ; Save the fifth parameter from the stack into a register (if necessary)
    mov     r10, rcx          ; Move rcx to r10 as per syscall convention
    mov     eax, 50h          ; Move syscall number into eax
    syscall                   ; Perform the syscall
    ret                       ; Return to caller
MyNtProtectVirtualMemory ENDP

END
