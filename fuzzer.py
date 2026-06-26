import math
import struct
import unicornafl

from unicorn import *
from unicorn.arm_const import *

allocs = {}

# load the firmware into memory
FIRMWARE = open("modem_firmware.bin", "rb").read()
BASE_ADDRESS = 0x50000

# start at modem_system_ram end - 4 to avoid going over the edge
STACK_ADDRESS = 0x20000000 + 0x8000 - 4

# start the heap in the middle of the ram
HEAP_ADDRESS = 0x30000000
HEAP_MAX = 0x30100000  # heap size 1MB
HEAP_PTR = HEAP_ADDRESS

# write AT string outside of heap to avoid overwriting in case of malloc
AT_STRING_ADDRESS = 0x31000000
MESSAGE_DATA_ADDR = 0x20003000

# emulation starting point: start of the process_message function in the firmware
process_message = 0x000DA7E0
EXIT_ADDRESS = 0xC0FFEE

# guard page size for heap allocations to detect overflows and underflows
GUARD_SIZE = 0x20


# we need to align the firmware size to 4KB for memory mapping
def align_size(bytes_size, four_kb=4096):
    return math.ceil(bytes_size / four_kb) * four_kb


def align_4_bytes(requested_size):
    return math.ceil(requested_size / 4) * 4


def hook_skip(uc, address, size, user_data):
    lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_PC, lr)


def hook_da004(uc, address, size, user_data):
    lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_R0, 0)
    uc.reg_write(UC_ARM_REG_PC, lr)


def hook_d7f10(uc, address, size, user_data):
    lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF)
    uc.reg_write(UC_ARM_REG_PC, lr)


def hook_d7748(uc, address, size, user_data):
    uc.mem_write(0x20002000, b"unknown string\x00")
    lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_R0, 0x20002000)
    uc.reg_write(UC_ARM_REG_PC, lr)


def hook_free(uc, address, size, user_data):
    malloc_ptr = uc.reg_read(UC_ARM_REG_R0)

    if malloc_ptr not in allocs:
        uc.reg_write(UC_ARM_REG_PC, 0xDEADBEEF)
        return

    requested_size, is_freed = allocs[malloc_ptr]

    if is_freed:
        uc.reg_write(UC_ARM_REG_PC, 0xDEADBEEF)
        return

    front_guard = uc.mem_read(malloc_ptr - GUARD_SIZE, GUARD_SIZE)
    back_guard = uc.mem_read(malloc_ptr + align_4_bytes(requested_size), GUARD_SIZE)

    if bytes(front_guard) != b"\xaa" * GUARD_SIZE:
        uc.reg_write(UC_ARM_REG_PC, 0xDEADBEEF)
        return

    if bytes(back_guard) != b"\xaa" * GUARD_SIZE:
        uc.reg_write(UC_ARM_REG_PC, 0xDEADBEEF)
        return

    allocs[malloc_ptr] = (requested_size, True)

    lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_PC, lr)


def hook_malloc(uc, address, size, user_data):
    global HEAP_PTR

    requested_size = uc.reg_read(UC_ARM_REG_R0)
    malloc_size = GUARD_SIZE + align_4_bytes(requested_size) + GUARD_SIZE

    if HEAP_PTR + malloc_size > HEAP_MAX:
        uc.reg_write(UC_ARM_REG_R0, 0)
    else:
        uc.mem_write(HEAP_PTR, b"\xaa" * GUARD_SIZE)
        HEAP_PTR += GUARD_SIZE

        req_size_ptr = HEAP_PTR
        HEAP_PTR += align_4_bytes(requested_size)

        uc.mem_write(HEAP_PTR, b"\xaa" * GUARD_SIZE)
        HEAP_PTR += GUARD_SIZE

        allocs[req_size_ptr] = (requested_size, False)
        uc.reg_write(UC_ARM_REG_R0, req_size_ptr)

    lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_PC, lr)


def hook_alloc_000d753e(uc, address, size, user_data):
    global HEAP_PTR

    num = uc.reg_read(UC_ARM_REG_R0)
    type_size = uc.reg_read(UC_ARM_REG_R1)
    requested_size = align_4_bytes(num * type_size)

    malloc_size = GUARD_SIZE + align_4_bytes(requested_size) + GUARD_SIZE

    if requested_size == 0:
        uc.reg_write(UC_ARM_REG_R0, 0)
    elif HEAP_PTR + malloc_size > HEAP_MAX:
        uc.reg_write(UC_ARM_REG_R0, 0)
    else:
        uc.mem_write(HEAP_PTR, b"\xaa" * GUARD_SIZE)
        HEAP_PTR += GUARD_SIZE

        req_size_ptr = HEAP_PTR
        HEAP_PTR += align_4_bytes(requested_size)

        uc.mem_write(HEAP_PTR, b"\xaa" * GUARD_SIZE)
        HEAP_PTR += GUARD_SIZE

        allocs[req_size_ptr] = (requested_size, False)
        uc.reg_write(UC_ARM_REG_R0, req_size_ptr)

    lr = uc.reg_read(UC_ARM_REG_LR)
    uc.reg_write(UC_ARM_REG_PC, lr)


# set up Unicorn emulator
try:
    # initialize emulator in ARM mode and thumb mode for Cortex-M ISA
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

    # map memory for the firmware needs to be aligned 4KB
    mu.mem_map(0x50000, align_size(len(FIRMWARE)))  # firmware ram

    # write the firmware to the mapped memory
    mu.mem_write(BASE_ADDRESS, FIRMWARE)

    # map memory regions
    mu.mem_map(0x0, 0x1000)  # modem_reg_dump
    mu.mem_map(0x240000, 0x40000)  # modem_fota_areaf
    mu.mem_map(0x800000, 0x8000)  # covers tcm_copy + tcm1
    mu.mem_map(0x80A000, 0x26000)  # covers tcm_copy2 + tcm2
    mu.mem_map(0x20000000, 0x8000)  # modem_system_ram
    mu.mem_map(0x22000000, 0x20000)  # modem_DSP_ram
    mu.mem_map(0x40000000, 0x20000000)  # peripheral
    mu.mem_map(0xE0000000, 0x20000000)  # system_SYS
    mu.mem_map(0x30000000, 0x100000)  # custom heap 1MB
    mu.mem_map(0x31000000, 0x100000)  # custom AT string

    mu.mem_write(0x800000, FIRMWARE[0x19658 : 0x19658 + 0x7C8])
    mu.mem_write(0x80A000, FIRMWARE[0x16F238 : 0x16F238 + 0x1E88])

    skip_addresses = [
        0x000D7EE6,  # sleep
        0x000DD190,  # FUN_000dd190
        0x000D84BC,  # FUN_000d84bc
        0x000D7EBC,  # FUN_000d7ebc
        0x00131CE8,  # pal_msg_send_to
        0x000D8562,  # FUN_000d8562
        0x000D84C4,  # FUN_000d84c4
        0x000D84AC,  # FUN_000d84ac
        0x000D8550,  # FUN_000d8550
        0x0012D534,  # diag tracing
        0x0012D55E,  # diag tracing
        0x00066998,  # diag tracing
        0x0012D348,  # diag tracing
        0x0012CF40,  # diag tracing
        0x00066A24,  # diag tracing
    ]

    for addr in skip_addresses:
        mu.hook_add(UC_HOOK_CODE, hook_skip, begin=addr, end=addr + 1)

    # functions with custom return values
    # we use seperate hook functions instead of a single hook function to avoid the command comparison bottleneck
    mu.hook_add(UC_HOOK_CODE, hook_da004, begin=0x000DA004, end=0x000DA004 + 1)
    mu.hook_add(UC_HOOK_CODE, hook_d7f10, begin=0x000D7F10, end=0x000D7F10 + 1)
    mu.hook_add(UC_HOOK_CODE, hook_d7748, begin=0x000D7748, end=0x000D7748 + 1)

    # free
    mu.hook_add(UC_HOOK_CODE, hook_free, begin=0x000D770E, end=0x000D770E + 1)

    # malloc functions
    mu.hook_add(UC_HOOK_CODE, hook_malloc, begin=0x000D7C16, end=0x000D7C16 + 1)
    mu.hook_add(UC_HOOK_CODE, hook_malloc, begin=0x0005C0F4, end=0x0005C0F4 + 1)
    mu.hook_add(UC_HOOK_CODE, hook_alloc_000d753e, begin=0x000D753E, end=0x000D753E + 1)

except UcError as e:
    exit(1)


# per-round fuzzing function that will be called by UnicornAFL
def place_afl_bytes(uc, input_bytes, persistent_round, data):
    global HEAP_PTR, allocs
    HEAP_PTR = HEAP_ADDRESS
    allocs = {}  # reset alloc dict each fuzz round

    if len(input_bytes) < 1:
        return False

    HEAP_PTR = HEAP_ADDRESS

    # we need to set modem to 1 or else it returns 7 in AT_validate_dispatch meaning that the modem is not ready
    uc.mem_write(0x0080BE07, b"\x01")

    # construct message struct (keep header fixed)
    command_id = 1
    flags = 0x00FF
    unknown_bytes = 0
    data_ptr = AT_STRING_ADDRESS  # point to the AT string in memory
    data_len = len(input_bytes)

    msg = struct.pack("<HHIII", command_id, flags, unknown_bytes, data_ptr, data_len)
    uc.mem_write(MESSAGE_DATA_ADDR, msg)

    uc.mem_write(AT_STRING_ADDRESS, input_bytes)
    uc.mem_write(AT_STRING_ADDRESS + len(input_bytes), b"\x00")

    # Reset CPU states for this round
    uc.reg_write(UC_ARM_REG_R0, MESSAGE_DATA_ADDR)
    uc.reg_write(UC_ARM_REG_SP, STACK_ADDRESS)
    uc.reg_write(UC_ARM_REG_LR, EXIT_ADDRESS)
    uc.reg_write(UC_ARM_REG_PC, process_message | 1)  # set LSB for thumb mode

    return True


# start fuzzing with UnicornAFL
input_file = None

result = unicornafl.uc_afl_fuzz(
    uc=mu,
    input_file=input_file,  # set to none to let AFL generate its own inputs
    place_input_callback=place_afl_bytes,
    exits=[EXIT_ADDRESS],
)
