section .data
    ; --- User Interface Strings ---
    prompt      db "Enter password length (4-255): ", 0
    prompt_len  equ $ - prompt - 1

    err_msg     db "Invalid length. Using default (16).", 0x0A
    err_len     equ $ - err_msg

    out_label     db "Generated password: ", 0
    out_label_len equ $ - out_label - 1

    ; --- Character Sets for Password Generation ---
    upper   db "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    UPPER_LEN equ $ - upper

    lower   db "abcdefghijklmnopqrstuvwxyz"
    LOWER_LEN equ $ - lower

    digits  db "0123456789"
    DIGIT_LEN equ $ - digits

    special db "!@#$%^&*()-_=+[]{}|;:,.<>?/"
    SPEC_LEN  equ $ - special

    all_chars db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"
    ALL_LEN   equ $ - all_chars

    ; --- Constants ---
    DEFAULT_LEN equ 16
    dev_urandom db "/dev/urandom", 0

section .bss
    ; --- Uninitialized Memory Buffers ---
    input_buf resb 16   ; Buffer to store user input for length
    password  resb 258  ; Buffer for the generated password (up to 255 chars + newline)
    rand_buf  resb 256  ; Buffer to store random bytes from /dev/urandom

section .text
    global _start       ; Declare entry point for the linker

; Macro to perform a modulo operation on an 8-bit value
; Divides AL by CL, storing the remainder in AH, then moves it back to AL
%macro MOD_BYTE 0
    xor   ah, ah        ; Clear AH before division
    div   cl            ; AL = AX / CL, AH = AX % CL
    mov   al, ah        ; Move remainder (modulo result) into AL
%endmacro

_start:
    ; --- 1. Prompt User for Length ---
    mov   rax, 1        ; syscall: sys_write
    mov   rdi, 1        ; file descriptor: stdout (1)
    lea   rsi, [rel prompt] ; pointer to prompt string
    mov   rdx, prompt_len   ; length of prompt
    syscall

    ; --- 2. Read User Input ---
    mov   rax, 0        ; syscall: sys_read
    xor   rdi, rdi      ; file descriptor: stdin (0)
    lea   rsi, [rel input_buf] ; pointer to input buffer
    mov   rdx, 15       ; max bytes to read
    syscall

    ; --- 3. Convert Input to Integer ---
    lea   rsi, [rel input_buf]
    call  atoi          ; Custom string-to-integer function, result in RAX

    ; --- 4. Validate Input Length ---
    cmp   rax, 4        ; Check if length < 4
    jl    .bad_length
    cmp   rax, 255      ; Check if length > 255
    jg    .bad_length
    mov   r12, rax      ; Store valid length in r12 (callee-saved register)
    jmp   .open_urandom ; Skip default length assignment

.bad_length:
    ; --- 5. Handle Invalid Length (Fallback to Default) ---
    mov   rax, 1        ; syscall: sys_write
    mov   rdi, 1        ; stdout
    lea   rsi, [rel err_msg] ; pointer to error message
    mov   rdx, err_len  ; length of error message
    syscall
    mov   r12, DEFAULT_LEN ; Set length to 16

.open_urandom:
    ; --- 6. Open /dev/urandom for Cryptographic Randomness ---
    mov   rax, 2        ; syscall: sys_open
    lea   rdi, [rel dev_urandom] ; filepath
    xor   rsi, rsi      ; flags: O_RDONLY (0)
    xor   rdx, rdx      ; mode: 0
    syscall
    test  rax, rax      ; Check if open failed (rax < 0)
    js    .exit_error
    mov   r13, rax      ; Store file descriptor in r13

    ; --- 7. Read Random Bytes ---
    mov   rax, 0        ; syscall: sys_read
    mov   rdi, r13      ; file descriptor for /dev/urandom
    lea   rsi, [rel rand_buf] ; destination buffer
    mov   rdx, r12      ; read 'length' amount of bytes
    syscall
    cmp   rax, r12      ; Verify we read the requested number of bytes
    jl    .exit_error

    ; --- 8. Close /dev/urandom ---
    mov   rax, 3        ; syscall: sys_close
    mov   rdi, r13      ; file descriptor
    syscall

    xor   r14, r14      ; Initialize password index counter to 0

    ; --- 9. Guarantee at least one of each character type ---
    
    ; Guarantee 1 uppercase letter
    movzx eax, byte [rand_buf + r14] ; Get a random byte
    mov   cl, UPPER_LEN              ; Modulo by length of uppercase string
    MOD_BYTE
    movzx rbx, al                    ; Use remainder as index
    mov   al, [upper + rbx]          ; Fetch character
    mov   [password + r14], al       ; Store in password buffer
    inc   r14

    ; Guarantee 1 lowercase letter
    movzx eax, byte [rand_buf + r14]
    mov   cl, LOWER_LEN
    MOD_BYTE
    movzx rbx, al
    mov   al, [lower + rbx]
    mov   [password + r14], al
    inc   r14

    ; Guarantee 1 digit
    movzx eax, byte [rand_buf + r14]
    mov   cl, DIGIT_LEN
    MOD_BYTE
    movzx rbx, al
    mov   al, [digits + rbx]
    mov   [password + r14], al
    inc   r14

    ; Guarantee 1 special character
    movzx eax, byte [rand_buf + r14]
    mov   cl, SPEC_LEN
    MOD_BYTE
    movzx rbx, al
    mov   al, [special + rbx]
    mov   [password + r14], al
    inc   r14

.fill_loop:
    ; --- 10. Fill the rest of the password length with mixed characters ---
    cmp   r14, r12      ; Check if we reached the requested length
    jge   .shuffle      ; If done, proceed to shuffle
    
    movzx eax, byte [rand_buf + r14] ; Get next random byte
    mov   cl, ALL_LEN                ; Modulo by total charset length
    MOD_BYTE
    movzx rbx, al
    mov   al, [all_chars + rbx]      ; Pick random char from all_chars
    mov   [password + r14], al       ; Append to password
    inc   r14
    jmp   .fill_loop

.shuffle:
    ; --- 11. Shuffle the Password (Fisher-Yates Shuffle) ---
    ; We need new random bytes for the shuffle indices, so reopen /dev/urandom
    mov   rax, 2        ; syscall: sys_open
    lea   rdi, [rel dev_urandom]
    xor   rsi, rsi
    xor   rdx, rdx
    syscall
    test  rax, rax
    js    .print        ; If open fails here, skip shuffle and just print
    mov   r13, rax      ; Store fd

    ; Read random bytes again
    mov   rax, 0        ; syscall: sys_read
    mov   rdi, r13
    lea   rsi, [rel rand_buf]
    mov   rdx, r12
    syscall

    ; Close fd
    mov   rax, 3        ; syscall: sys_close
    mov   rdi, r13
    syscall

    mov   r9, r12       ; r9 = loop counter starting at (length - 1)
    dec   r9

.shuffle_loop:
    ; Fisher-Yates algorithm: iterate backwards and swap with random previous element
    cmp   r9, 1
    jl    .print        ; Stop shuffling when index reaches 0

    movzx eax, byte [rand_buf + r9] ; Get random byte for index calculation
    mov   r10, r9
    inc   r10           ; r10 = current index + 1 (the upper bound exclusive)
    xor   edx, edx      ; Clear edx before division
    div   r10d          ; Divide random byte by (index + 1)
    mov   rbx, rdx      ; Remainder is our random swap index (0 to current index)

    ; Perform the swap in the password buffer
    movzx eax, byte [password + r9]  ; Char at current index
    movzx ecx, byte [password + rbx] ; Char at random index
    mov   [password + r9],  cl       ; Put random char at current index
    mov   [password + rbx], al       ; Put current char at random index

    dec   r9            ; Move to previous character
    jmp   .shuffle_loop

.print:
    ; --- 12. Output the Result ---
    
    ; Print "Generated password: "
    mov   rax, 1
    mov   rdi, 1
    lea   rsi, [rel out_label]
    mov   rdx, out_label_len
    syscall

    ; Append a newline character to the end of the generated password
    mov   byte [password + r12], 0x0A

    ; Print the actual password
    mov   rax, 1
    mov   rdi, 1
    lea   rsi, [rel password]
    mov   rdx, r12
    inc   rdx           ; Length + 1 to include the newline
    syscall

    ; --- 13. Normal Exit ---
    mov   rax, 60       ; syscall: sys_exit
    xor   rdi, rdi      ; exit code 0
    syscall

.exit_error:
    ; --- Error Exit ---
    mov   rax, 60       ; syscall: sys_exit
    mov   rdi, 1        ; exit code 1
    syscall

; --- Helper Function: String to Integer (atoi) ---
; Expects RSI to point to the string. Returns parsed integer in RAX.
atoi:
    xor   rax, rax      ; Initialize result to 0
    xor   rcx, rcx      ; Clear rcx for reading characters
.atoi_loop:
    movzx ecx, byte [rsi] ; Load next character
    cmp   cl, 0x0A      ; Check for newline (\n)
    je    .atoi_done
    test  cl, cl        ; Check for null terminator (\0)
    jz    .atoi_done
    
    sub   cl, '0'       ; Convert ASCII to integer value
    js    .atoi_done    ; If result is negative, it wasn't a digit (e.g., space)
    cmp   cl, 9         ; Check if it's > 9
    jg    .atoi_done    ; If greater, it wasn't a digit
    
    imul  rax, rax, 10  ; Multiply current result by 10
    add   rax, rcx      ; Add the new digit
    inc   rsi           ; Move to next character in string
    jmp   .atoi_loop
.atoi_done:
    ret                 ; Return to caller
