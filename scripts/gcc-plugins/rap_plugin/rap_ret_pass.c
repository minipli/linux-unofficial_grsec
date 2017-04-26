/*
 * Copyright 2012-2017 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Homepage: http://pax.grsecurity.net/
 */

#include "rap.h"

bool rap_cmodel_check(void)
{
#ifdef TARGET_386
	tree section;

	if (!TARGET_64BIT || ix86_cmodel != CM_KERNEL)
		return true;

	section = lookup_attribute("section", DECL_ATTRIBUTES(current_function_decl));
	if (!section || !TREE_VALUE(section))
		return true;

	section = TREE_VALUE(TREE_VALUE(section));
	return strncmp(TREE_STRING_POINTER(section), ".vsyscall_", 10);
#else
#error unsupported target
#endif
}

static bool rap_ret_gate(void)
{
	return rap_cmodel_check();
}

tree create_new_var(tree type, const char *name)
{
	tree var;

	var = create_tmp_var(type, name);
	add_referenced_var(var);
//	mark_sym_for_renaming(var);
	return var;
}

/*
 * insert the equivalent of
 * return (unsigned long)__builtin_return_address(0);
 */
static tree get_retaddr(gimple_seq *stmts)
{
	gimple stmt;
	tree retaddr_ptr;

	stmt = barrier(NULL_TREE, true);
	gimple_seq_add_stmt(stmts, stmt);

	// copy the return address into a temporary variable
	retaddr_ptr = create_new_var(ptr_type_node, "rap_retaddr_exit_ptr");
	stmt = gimple_build_call(builtin_decl_implicit(BUILT_IN_RETURN_ADDRESS), 1, integer_zero_node);
	retaddr_ptr = make_ssa_name(retaddr_ptr, stmt);
	gimple_call_set_lhs(stmt, retaddr_ptr);
	gimple_seq_add_stmt(stmts, stmt);

	return retaddr_ptr;
}

/*
 * insert the equivalent of
 * if (*(long *)((void *)retaddr+N) != (long)-function_hash) abort();
 */
static void check_retaddr(gimple_stmt_iterator *gsi, tree new_retaddr)
{
	gimple stmt;
	location_t loc;
	basic_block cond_bb, join_bb, true_bb;
	edge e;

	gcc_assert(!gsi_end_p(*gsi));
	loc = gimple_location(gsi_stmt(*gsi));

	gimple_seq stmts = NULL;
	tree target_hash, computed_hash;
	rap_hash_t hash;

#ifdef TARGET_386
	if (TARGET_64BIT)
		target_hash = get_rap_hash(&stmts, loc, new_retaddr, -16);
	else
		target_hash = get_rap_hash(&stmts, loc, new_retaddr, -10);
#else
#error unsupported target
#endif

	if (gsi_end_p(*gsi) || !stmt_ends_bb_p(gsi_stmt(*gsi)))
		gsi_insert_seq_after(gsi, stmts, GSI_CONTINUE_LINKING);
	else {
		gsi_insert_seq_before(gsi, stmts, GSI_SAME_STMT);
		gsi_prev(gsi);
	}

	hash = rap_hash_function_type(TREE_TYPE(current_function_decl), imprecise_rap_hash_flags);
	computed_hash = build_int_cst_type(rap_hash_type_node, -hash.hash);

	stmt = gimple_build_cond(NE_EXPR, target_hash, computed_hash, NULL_TREE, NULL_TREE);
	gimple_set_location(stmt, loc);
	gsi_insert_after(gsi, stmt, GSI_CONTINUE_LINKING);

	cond_bb = gimple_bb(gsi_stmt(*gsi));
	e = split_block(cond_bb, gsi_stmt(*gsi));
	cond_bb = e->src;
	join_bb = e->dest;
	e->flags = EDGE_FALSE_VALUE;
	e->probability = REG_BR_PROB_BASE;

	true_bb = create_empty_bb(join_bb);
	make_edge(cond_bb, true_bb, EDGE_TRUE_VALUE | EDGE_PRESERVE);

	set_immediate_dominator(CDI_DOMINATORS, true_bb, cond_bb);
	set_immediate_dominator(CDI_DOMINATORS, join_bb, cond_bb);

	gcc_assert(cond_bb->loop_father == join_bb->loop_father);
	add_bb_to_loop(true_bb, cond_bb->loop_father);

	// insert call to builtin_trap or rap_abort_ret
	*gsi = gsi_start_bb(true_bb);

	if (rap_abort_ret) {
		stmt = gimple_build_asm_vec(rap_abort_ret, NULL, NULL, NULL, NULL);
		gimple_asm_set_volatile(as_a_gasm(stmt), true);
		gimple_set_location(stmt, loc);
		gsi_insert_after(gsi, stmt, GSI_CONTINUE_LINKING);

		stmt = gimple_build_call(builtin_decl_implicit(BUILT_IN_UNREACHABLE), 0);
	} else
		stmt = gimple_build_call(builtin_decl_implicit(BUILT_IN_TRAP), 0);

	gimple_set_location(stmt, loc);
	gsi_insert_after(gsi, stmt, GSI_CONTINUE_LINKING);

	*gsi = gsi_after_labels(join_bb);
}

static unsigned int rap_ret_execute(void)
{
	edge e;
	edge_iterator ei;

	loop_optimizer_init(LOOPS_NORMAL | LOOPS_HAVE_RECORDED_EXITS);
	gcc_assert(current_loops);

	calculate_dominance_info(CDI_DOMINATORS);
	calculate_dominance_info(CDI_POST_DOMINATORS);

	FOR_EACH_EDGE(e, ei, EXIT_BLOCK_PTR_FOR_FN(cfun)->preds) {
		gimple_stmt_iterator gsi;
		gimple_seq stmts = NULL;
		tree new_retaddr;

		gsi = gsi_last_nondebug_bb(e->src);
		gcc_assert(!gsi_end_p(gsi));
		gcc_assert(gimple_code(gsi_stmt(gsi)) == GIMPLE_RETURN);

		new_retaddr = get_retaddr(&stmts);
		gsi_insert_seq_before(&gsi, stmts, GSI_SAME_STMT);
		gsi_prev(&gsi);
		check_retaddr(&gsi, new_retaddr);
	}

	free_dominance_info(CDI_DOMINATORS);
	free_dominance_info(CDI_POST_DOMINATORS);
	loop_optimizer_finalize();
	return 0;
}

#define PASS_NAME rap_ret
#define PROPERTIES_REQUIRED PROP_cfg
#define TODO_FLAGS_FINISH TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_remove_unused_locals | TODO_update_ssa | TODO_cleanup_cfg | TODO_ggc_collect | TODO_rebuild_cgraph_edges | TODO_verify_flow
#include "gcc-generate-gimple-pass.h"

// find and remove the asm mark from the given insn up in its basic block
static tree rap_find_retloc_mark(rtx_insn *insn)
{
	basic_block bb;
	rtx_insn *hash;

#if BUILDING_GCC_VERSION == 4005
	FOR_EACH_BB_FN(bb, cfun) {
		rtx_insn *i;

		FOR_BB_INSNS(bb, i) {
			if (i == insn)
				break;
		}
		if (i == insn)
			break;
	}
#else
	bb = BLOCK_FOR_INSN(insn);
#endif
	gcc_assert(bb);
	gcc_assert(BB_HEAD(bb));

	for (hash = insn; hash && hash != PREV_INSN(BB_HEAD(bb)); hash = PREV_INSN(hash)) {
		tree computed_hash;
		rtx body;

		if (!INSN_P(hash))
			continue;

		body = PATTERN(hash);

		if (GET_CODE(body) != PARALLEL)
			continue;

		body = XVECEXP(body, 0, 0);
		if (GET_CODE(body) != ASM_OPERANDS)
			continue;

		if (ASM_OPERANDS_INPUT_LENGTH(body) != 1)
			continue;

		body = ASM_OPERANDS_INPUT(body, 0);
		if (!CONST_INT_P(body))
			continue;

		computed_hash = build_int_cst_type(rap_hash_type_node, INTVAL(body));
		delete_insn_and_edges(hash);
		return computed_hash;;
	}

	return NULL_TREE;
}

static tree rap_get_direct_call_retloc_mark(rtx_insn *insn)
{
	rap_hash_t func_hash;
	rtx body;
	tree fntype;

	body = PATTERN(insn);
	if (GET_CODE(body) == SET)
		body = SET_SRC(body);
	if (GET_CODE(body) != CALL)
		return NULL_TREE;

	body = XEXP(body, 0);
	gcc_assert(GET_CODE(body) == MEM);
	if (GET_CODE(XEXP(body, 0)) != SYMBOL_REF)
		return NULL_TREE;

	fntype = SYMBOL_REF_DECL(XEXP(body, 0));
	gcc_assert(TREE_CODE(fntype) == FUNCTION_DECL);
	fntype = TREE_TYPE(fntype);
	func_hash = rap_hash_function_type(fntype, imprecise_rap_hash_flags);
	return build_int_cst_type(rap_hash_type_node, -func_hash.hash);
}

static unsigned int rap_mark_retloc_execute(void)
{
	rtx_insn *insn;

	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		rtvec argvec, constraintvec, labelvec;
		rtx mark, label1, label2;
		tree computed_hash = NULL_TREE;

		if (INSN_DELETED_P(insn))
			continue;

		// rtl match (call_insn (set (reg) (call (mem))))
		if (!CALL_P(insn))
			continue;

		gcc_assert(!SIBLING_CALL_P(insn));

		if (find_reg_note(insn, REG_NORETURN, 0))
			continue;

		argvec = rtvec_alloc(1);
		constraintvec = rtvec_alloc(1);
		labelvec = rtvec_alloc(2);

#ifdef TARGET_386
		if (TARGET_64BIT)
			mark = gen_rtx_ASM_OPERANDS(VOIDmode, ggc_strdup("jmp %l1 ; .quad %c0 ; .skip 8-(%l2-%l1),0xcc"), empty_string, 0, argvec, constraintvec, labelvec, INSN_LOCATION(insn));
		else
			mark = gen_rtx_ASM_OPERANDS(VOIDmode, ggc_strdup("jmp %l1 ; .long %c0 ; .skip 6-(%l2-%l1),0xcc"), empty_string, 0, argvec, constraintvec, labelvec, INSN_LOCATION(insn));
#else
#error unsupported target
#endif
		MEM_VOLATILE_P(mark) = 1;

		computed_hash = rap_find_retloc_mark(insn);

		// gcc can insert calls to memcpy/memmove/etc in RTL
		if (!computed_hash)
			computed_hash = rap_get_direct_call_retloc_mark(insn);

		// due to optimizations, the return location mark(s) could have ended up in preceding blocks
		if (!computed_hash) {
			edge e;
			edge_iterator ei;
			tree h;

			FOR_EACH_EDGE(e, ei, BLOCK_FOR_INSN(insn)->preds) {
				gcc_assert(single_succ_p(e->src));
				h = rap_find_retloc_mark(BB_END(e->src));
				gcc_assert(h);

				if (computed_hash)
					gcc_assert(tree_to_shwi(h) == tree_to_shwi(computed_hash));
				else
					computed_hash = h;
			}
		}

		gcc_assert(computed_hash);
		ASM_OPERANDS_INPUT(mark, 0) = expand_expr(computed_hash, NULL_RTX, VOIDmode, EXPAND_INITIALIZER);

		ASM_OPERANDS_INPUT_CONSTRAINT_EXP(mark, 0) = gen_rtx_ASM_INPUT_loc(DImode, ggc_strdup("i"), UNKNOWN_LOCATION);

		label1 = gen_label_rtx();
		label2 = gen_label_rtx();
		ASM_OPERANDS_LABEL(mark, 0) = label1;
		ASM_OPERANDS_LABEL(mark, 1) = label2;

		emit_insn_before(mark, insn);

		emit_label_before(label1, insn);
		LABEL_NUSES(label1)++;
		do {
			insn = NEXT_INSN(insn);
		} while (GET_CODE(insn) == NOTE && NOTE_KIND(insn) == NOTE_INSN_CALL_ARG_LOCATION);
		emit_label_before(label2, insn);
		LABEL_NUSES(label2)++;
	}

	return 0;
}

#define PASS_NAME rap_mark_retloc
#define NO_GATE
#define TODO_FLAGS_FINISH TODO_dump_func | TODO_verify_rtl_sharing
#include "gcc-generate-rtl-pass.h"
