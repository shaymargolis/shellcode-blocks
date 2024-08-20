#include "goto.h"

goto:
	lui $v0, %hi(GOTO_ADDRESS)
	addiu $v0, %lo(GOTO_ADDRESS)
	nop
	jr $v0
	nop
