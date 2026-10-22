.include "m328Pdef.inc"

.org 0x0000
    rjmp Reset

Reset:
    ldi r16, low(RAMEND)
    out SPL, r16
    ldi r16, high(RAMEND)
    out SPH, r16
    sbi DDRB, 5
    cbi PORTB, 5
