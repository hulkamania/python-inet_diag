#ifndef _DIAG_FILTER_H_
#define _DIAG_FILTER_H_ 1

#define DIAG_FILTER_OR	1
#define DIAG_FILTER_AND	2
#define DIAG_FILTER_NOT	3
#define DIAG_BC_NOP 4
#define DIAG_BC_JMP 5
#define DIAG_BC_S_GE 6
#define DIAG_BC_S_LE 7
#define DIAG_BC_D_GE 8
#define DIAG_BC_D_LE 9
#define DIAG_BC_AUTO 10
#define DIAG_BC_S_COND 11
#define DIAG_BC_D_COND 12

#include <linux/types.h>

/* Simple filter using the INET_DIAG_BC_* types */
struct diag_filter {
	int type;
	int value;
	struct diag_filter *post;
	struct diag_filter *pred;
};
#endif /* _DIAG_FILTER_H_ */
