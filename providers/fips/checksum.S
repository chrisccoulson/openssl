    .globl  module_checksum
    .size   module_checksum, 32
    .type   module_checksum, %object
    .section .module-checksum, "a", %progbits
module_checksum:
    .zero 32
