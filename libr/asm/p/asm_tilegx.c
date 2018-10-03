/* radare - LGPL - Copyright 2014-2018 - fedor.sakharov */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	r_strbuf_set (&op->buf_asm, sdb_fmt ("test"));
	return 8;
}

RAsmPlugin r_asm_plugin_tilegx = {
	.name = "tilegx",
	.license = "LGPL3",
	.desc = "Tilera TILE-Gx disassembly plugin",
	.arch = "tilegx",
	.bits = 64,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_tilegx,
	.version = R2_VERSION
};
#endif
