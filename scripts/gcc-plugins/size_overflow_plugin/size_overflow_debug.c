/*
 * Copyright 2011-2017 by Emese Revfy <re.emese@gmail.com>
 * Licensed under the GPL v2
 *
 * Homepage:
 * https://github.com/ephox-gcc-plugins/size_overflow
 *
 * Documentation:
 * http://forums.grsecurity.net/viewtopic.php?f=7&t=3043
 *
 * This plugin recomputes expressions of function arguments marked by a size_overflow attribute
 * with double integer precision (DImode/TImode for 32/64 bit integer types).
 * The recomputed argument is checked against TYPE_MAX and an event is logged on overflow and the triggering process is killed.
 *
 * Usage:
 * $ make
 * $ make run
 */

#include "size_overflow.h"

void __unused print_intentional_mark(enum intentional_mark mark)
{
	fprintf(stderr, "intentional mark: ");
	switch (mark) {
	case MARK_NO:
		fprintf(stderr, "mark_no\n");
		break;
	case MARK_YES:
		fprintf(stderr, "mark_yes\n");
		break;
	case MARK_TURN_OFF:
		fprintf(stderr, "mark_turn_off\n");
		break;
	case MARK_END_INTENTIONAL:
		fprintf(stderr, "mark_end_intentional\n");
		break;
	}
}

unsigned int __unused size_overflow_dump_function(FILE *file, struct cgraph_node *node)
{
	basic_block bb;

	fprintf(file, "dump_function function_name: %s\n", cgraph_node_name(node));

	fprintf(file, "\nstmts:\n");
	FOR_EACH_BB_FN(bb, DECL_STRUCT_FUNCTION(NODE_DECL(node))) {
		gimple_stmt_iterator si;

		fprintf(file, "<bb %u>:\n", bb->index);
		for (si = gsi_start_phis(bb); !gsi_end_p(si); gsi_next(&si))
			print_gimple_stmt(file, gsi_stmt(si), 0, TDF_VOPS|TDF_MEMSYMS);
		for (si = gsi_start_bb(bb); !gsi_end_p(si); gsi_next(&si))
			print_gimple_stmt(file, gsi_stmt(si), 0, TDF_VOPS|TDF_MEMSYMS);
		fprintf(file, "\n");
	}

	fprintf(file, "---------------------------------\n");

	return 0;
}

void __unused print_next_interesting_function(next_interesting_function_t node)
{
	unsigned int i, children_len;
	next_interesting_function_t cur;

	if (!node)
		return;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, node->children))
		children_len = 0;
	else
		children_len = VEC_length(next_interesting_function_t, node->children);
#else
	children_len = vec_safe_length(node->children);
#endif

	fprintf(stderr, "print_next_interesting_function: ptr: %p, ", node);
	fprintf(stderr, "decl_name: %s, based_decl: %s, ", node->decl_name, get_based_decl_str(node->based_decl));

	fprintf(stderr, "num: %u marked: %s context: %s children len: %u\n", node->num, print_so_mark_name(node->marked), node->context, children_len);
#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, node->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, node->children, i, cur) {
#else
	FOR_EACH_VEC_SAFE_ELT(node->children, i, cur) {
#endif
		fprintf(stderr, "\t%u. child: %s %u %p marked: %s context: %s\n", i + 1, cur->decl_name, cur->num, cur, print_so_mark_name(cur->marked), cur->context);
	}
}

// Dump the full next_interesting_function_t list for parsing by print_dependecy.py
void __unused print_next_interesting_functions_chain(next_interesting_function_t head, bool only_this)
{
	next_interesting_function_t cur;
	unsigned int len;

	fprintf(stderr, "----------------------\nnext_interesting_function_t head: %p\n", head);
	for (cur = head, len = 0; cur; cur = cur->next, len++) {
		fprintf(stderr, "%u. ", len + 1);
		print_next_interesting_function(cur);

		fprintf(stderr, "+++++ has orig node: %p +++++\n", cur->orig_next_node);
		print_next_interesting_function(cur->orig_next_node);

		if (only_this)
			break;
	}

	fprintf(stderr, "len: %u\n----------------------\n\n\n", len + 1);
}

void __unused print_global_next_interesting_functions(void)
{
	unsigned int i;

	fprintf(stderr, "----------------------\nprint_global_next_interesting_functions:\n----------------------\n");
	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		if (!global_next_interesting_function[i])
			continue;
		fprintf(stderr, "hash: %u\n", i);
		print_next_interesting_functions_chain(global_next_interesting_function[i], false);
	}
	fprintf(stderr, "----------------------\n\n");
}

// Dump the information related to the specified next_interesting_function_t for parsing by print_dependecy.py
void __unused print_children_chain_list(next_interesting_function_t next_node)
{
	next_interesting_function_t cur;
	unsigned int i;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, next_node->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, next_node->children, i, cur) {
#else
	FOR_EACH_VEC_SAFE_ELT(next_node->children, i, cur) {
#endif
		fprintf(stderr, "parent: %s %u (marked: %s) child: %s %u\n", next_node->decl_name, next_node->num, print_so_mark_name(next_node->marked), cur->decl_name, cur->num);
		print_children_chain_list(cur);
	}
}

void __unused print_all_next_node_children_chain_list(next_interesting_function_t head)
{
	next_interesting_function_t cur;

	for (cur = head; cur; cur = cur->next) {
#if BUILDING_GCC_VERSION <= 4007
		if (VEC_empty(next_interesting_function_t, cur->children))
#else
		if (vec_safe_length(cur->children) == 0)
#endif
			continue;
		fprintf(stderr, "############ START ############\n");
		print_children_chain_list(cur);
		fprintf(stderr, "############ END ############\n");
	}
}

const char * __unused print_intentional_mark_name(enum intentional_mark mark)
{
	switch(mark) {
	case MARK_NO:
		return "mark no";
	case MARK_YES:
		return "mark yes";
	case MARK_END_INTENTIONAL:
		return "mark end intetional";
	case MARK_TURN_OFF:
		return "mark turn off";
	}

	gcc_unreachable();
}

const char * __unused print_so_mark_name(enum size_overflow_mark mark)
{
	switch(mark) {
	case ASM_STMT_SO_MARK:
		return "asm_stmt_so_mark";
	case YES_SO_MARK:
		return "yes_so_mark";
	case NO_SO_MARK:
		return "no_so_mark";
	}

	gcc_unreachable();
}

void __unused print_raw_data(struct fn_raw_data *data)
{
	fprintf(stderr, "decl_str: %s, context: %s, num: %u, hash: %u\ndecl:\n", data->decl_str ? data->decl_str : "NULL", data->context ? data->context : "NULL", data->num, data->hash);
	debug_tree(data->decl);
	fprintf(stderr, "marked: %s, based_decl: %s\norig_decl_str: %s, orig_num: %u\n", print_so_mark_name(data->marked), get_based_decl_str(data->based_decl), data->orig_decl_str? data->orig_decl_str : "NULL", data->orig_num);
}
