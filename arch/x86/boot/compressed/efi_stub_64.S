#include <asm/segment.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>

#define efi_call efi_call_early
#include "../../platform/efi/efi_stub_64.S"
