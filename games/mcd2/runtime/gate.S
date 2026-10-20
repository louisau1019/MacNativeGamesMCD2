.text
.globl _runtime_gate
.p2align 2
_runtime_gate:
    mov x0, x30
    bl _runtime_on_gate
    ret
