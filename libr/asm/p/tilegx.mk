OBJ_TILEGX=asm_tilegx.o

STATIC_OBJ+=${OBJ_TILEGX}
TARGET_TILEGX=asm_tilegx.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_TILEGX}

${TARGET_TILEGX}: ${OBJ_TILEGX}
	${CC} ${LDFLAGS} ${CFLAGS} -o ${TARGET_TILEGX} ${OBJ_TILEGX}
endif