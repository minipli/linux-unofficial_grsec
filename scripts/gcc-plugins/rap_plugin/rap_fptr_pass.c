/*
 * Copyright 2012-2017 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Homepage: http://pax.grsecurity.net/
 */

#include "rap.h"

bool report_fptr_hash;

static bool rap_fptr_gate(void)
{
	return rap_cmodel_check();
}

static tree build_rap_hash(gimple call_stmt, tree fntype)
{
	rap_hash_t hash;

	hash = rap_hash_function_type(fntype, imprecise_rap_hash_flags);
	if (report_fptr_hash)
		inform(gimple_location(call_stmt), "fptr rap_hash: %x", hash.hash);
	return build_int_cst_type(rap_hash_type_node, hash.hash);
}

// extract the rap_hash stored at an offset from ptr
tree get_rap_hash(gimple_seq *stmts, location_t loc, tree fptr, HOST_WIDE_INT rap_hash_offset)
{
	gimple assign_hash;
	tree target_hash;
#if BUILDING_GCC_VERSION == 4005
	tree fptr2;
#endif

	// target_hash = *(long*)((void*)fptr + rap_hash_offset)
	target_hash = create_tmp_var(rap_hash_type_node, "rap_hash");
	add_referenced_var(target_hash);
	target_hash = make_ssa_name(target_hash, NULL);
#if BUILDING_GCC_VERSION == 4005
	fptr2 = create_tmp_var(ptr_type_node, "rap_fptr2");
	fptr2 = make_ssa_name(fptr2, NULL);
	assign_hash = gimple_build_assign(fptr2, build2(POINTER_PLUS_EXPR, ptr_type_node, fptr, build_int_cst_type(sizetype, rap_hash_offset)));
	gimple_set_location(assign_hash, loc);
	SSA_NAME_DEF_STMT(fptr2) = assign_hash;
	gimple_seq_add_stmt(stmts, assign_hash);
	fptr = gimple_get_lhs(assign_hash);

	fptr2 = create_tmp_var(build_pointer_type(rap_hash_type_node), "rap_fptr2");
	fptr2 = make_ssa_name(fptr2, NULL);
	assign_hash = gimple_build_assign(fptr2, fold_convert(build_pointer_type(TREE_TYPE(target_hash)), fptr));
	gimple_set_location(assign_hash, loc);
	SSA_NAME_DEF_STMT(fptr2) = assign_hash;
	gimple_seq_add_stmt(stmts, assign_hash);
	fptr = gimple_get_lhs(assign_hash);

	assign_hash = gimple_build_assign(target_hash, build1(INDIRECT_REF, rap_hash_type_node, fptr));
#else
	assign_hash = gimple_build_assign(target_hash, build2(MEM_REF, rap_hash_type_node, fptr, build_int_cst_type(build_pointer_type(rap_hash_type_node), rap_hash_offset)));
#endif
	gimple_set_location(assign_hash, loc);
	SSA_NAME_DEF_STMT(target_hash) = assign_hash;
	gimple_seq_add_stmt(stmts, assign_hash);

	return target_hash;
}

static void rap_mark_retloc(gimple_stmt_iterator *gsi, tree computed_hash)
{
	gimple stmt;
	VEC(tree, gc) *inputs = NULL;
	VEC(tree, gc) *clobbers = NULL;
	tree input, clobber, fndecl;

	fndecl = gimple_call_fndecl(gsi_stmt(*gsi));
	if (fndecl && is_simple_builtin(fndecl))
		return;

	input = build_tree_list(NULL_TREE, build_const_char_string(2, "i"));
	input = chainon(NULL_TREE, build_tree_list(input, computed_hash));
	VEC_safe_push(tree, gc, inputs, input);

	clobber = build_tree_list(NULL_TREE, build_const_char_string(3, "cx"));
	VEC_safe_push(tree, gc, clobbers, clobber);

	stmt = gimple_build_asm_vec("", inputs, NULL, NULL, NULL);
	gimple_asm_set_volatile(as_a_gasm(stmt), true);
	gimple_set_location(stmt, gimple_location(gsi_stmt(*gsi)));
	gsi_insert_before(gsi, stmt, GSI_SAME_STMT);
}

// check the function hash of the target of the fptr
static void rap_instrument_fptr(gimple_stmt_iterator *gsi)
{
	gimple check_hash, call_stmt, stmt;
	gimple_seq stmts = NULL;
	location_t loc;
	tree computed_hash, target_hash, fptr, fntype;
	basic_block cond_bb, join_bb, true_bb;
	edge e;
	HOST_WIDE_INT rap_hash_offset;

	call_stmt = gsi_stmt(*gsi);
	loc = gimple_location(call_stmt);
	fptr = gimple_call_fn(call_stmt);
	fntype = TREE_TYPE(TREE_TYPE(fptr));

	if (TREE_CODE(fntype) == FUNCTION_TYPE) {
		computed_hash = build_rap_hash(call_stmt, fntype);
	} else {
		debug_tree(fntype);
		gcc_unreachable();
	}

	if (UNITS_PER_WORD == 8)
		rap_hash_offset = 2 * sizeof(rap_hash_t);
	else if (UNITS_PER_WORD == 4)
		rap_hash_offset =  sizeof(rap_hash_t);
	else
		gcc_unreachable();

	target_hash = get_rap_hash(&stmts, loc, fptr, -rap_hash_offset);
	gsi_insert_seq_before(gsi, stmts, GSI_SAME_STMT);

	// compare target_hash against computed function hash
	// bail out on mismatch
	check_hash = gimple_build_cond(NE_EXPR, target_hash, computed_hash, NULL_TREE, NULL_TREE);
	gimple_set_location(check_hash, loc);
	gsi_insert_before(gsi, check_hash, GSI_NEW_STMT);

	cond_bb = gimple_bb(gsi_stmt(*gsi));
	gcc_assert(!gsi_end_p(*gsi));
	gcc_assert(check_hash == gsi_stmt(*gsi));

	e = split_block(cond_bb, gsi_stmt(*gsi));
	cond_bb = e->src;
	join_bb = e->dest;
	e->flags = EDGE_FALSE_VALUE;
	e->probability = REG_BR_PROB_BASE;

	true_bb = create_empty_bb(EXIT_BLOCK_PTR_FOR_FN(cfun)->prev_bb);
	make_edge(cond_bb, true_bb, EDGE_TRUE_VALUE | EDGE_PRESERVE);

	gcc_assert(dom_info_available_p(CDI_DOMINATORS));
	set_immediate_dominator(CDI_DOMINATORS, true_bb, cond_bb);
	set_immediate_dominator(CDI_DOMINATORS, join_bb, cond_bb);

	gcc_assert(cond_bb->loop_father == join_bb->loop_father);
	add_bb_to_loop(true_bb, cond_bb->loop_father);

	*gsi = gsi_start_bb(true_bb);

	if (rap_abort_call) {
		stmt = gimple_build_asm_vec(rap_abort_call, NULL, NULL, NULL, NULL);
		gimple_asm_set_volatile(as_a_gasm(stmt), true);
		gimple_set_location(stmt, loc);
		gsi_insert_after(gsi, stmt, GSI_CONTINUE_LINKING);

		stmt = gimple_build_call(builtin_decl_implicit(BUILT_IN_UNREACHABLE), 0);
	} else {
		// this fake dependency is to prevent PRE from merging this BB with others of the same kind
		stmt = barrier(fptr, false);
		gimple_set_location(stmt, loc);
		gsi_insert_after(gsi, stmt, GSI_CONTINUE_LINKING);

		stmt = gimple_build_call(builtin_decl_implicit(BUILT_IN_TRAP), 0);
	}

	gimple_set_location(stmt, loc);
	gsi_insert_after(gsi, stmt, GSI_CONTINUE_LINKING);

	*gsi = gsi_start_bb(join_bb);
}

// find all language level function pointer dereferences and verify the target function
static unsigned int rap_fptr_execute(void)
{
	basic_block bb;

	loop_optimizer_init(LOOPS_NORMAL | LOOPS_HAVE_RECORDED_EXITS);
	gcc_assert(current_loops);

	calculate_dominance_info(CDI_DOMINATORS);
	calculate_dominance_info(CDI_POST_DOMINATORS);

	// 1. loop through BBs and GIMPLE statements
	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			// gimple match: h_1 = get_fptr (); D.2709_3 = h_1 (x_2(D));
			tree fptr, fntype, computed_hash;
			gimple call_stmt;
			rap_hash_t hash;

			// is it a call ...
			call_stmt = gsi_stmt(gsi);
			if (!is_gimple_call(call_stmt))
				continue;

			fptr = gimple_call_fn(call_stmt);
			if (!fptr)
				continue;

			switch (TREE_CODE(fptr)) {
			default:
				debug_gimple_stmt(call_stmt);
				debug_tree(fptr);
				debug_tree(TREE_TYPE(fptr));
				gcc_unreachable();

			case ADDR_EXPR:
				hash = rap_hash_function_type(TREE_TYPE(TREE_OPERAND(fptr, 0)), imprecise_rap_hash_flags);
				computed_hash = build_int_cst_type(rap_hash_type_node, -hash.hash);
				rap_mark_retloc(&gsi, computed_hash);
				continue;

			case SSA_NAME:
				if (SSA_NAME_VAR(fptr) == NULL_TREE)
					break;

				switch (TREE_CODE(SSA_NAME_VAR(fptr))) {
				default:
					debug_gimple_stmt(call_stmt);
					debug_tree(fptr);
					gcc_unreachable();

				case VAR_DECL:
				case PARM_DECL:
					break;
				}
				break;

			case INTEGER_CST:
			case OBJ_TYPE_REF:
				break;
			}

			// ... through a function pointer
			fntype = TREE_TYPE(fptr);
			if (TREE_CODE(fntype) != POINTER_TYPE) {
				gcc_assert(TREE_CODE(fntype) == FUNCTION_TYPE || TREE_CODE(fntype) == METHOD_TYPE);
				hash = rap_hash_function_type(fntype, imprecise_rap_hash_flags);
				computed_hash = build_int_cst_type(rap_hash_type_node, -hash.hash);
				rap_mark_retloc(&gsi, computed_hash);
				continue;
			}

			fntype = TREE_TYPE(fntype);
			gcc_assert(TREE_CODE(fntype) == FUNCTION_TYPE || TREE_CODE(fntype) == METHOD_TYPE);

			if (enable_type_call) {
				rap_instrument_fptr(&gsi);
				bb = gsi_bb(gsi);
				gcc_assert(call_stmt == gsi_stmt(gsi));
			}

			if (enable_type_ret) {
				hash = rap_hash_function_type(fntype, imprecise_rap_hash_flags);
				computed_hash = build_int_cst_type(rap_hash_type_node, -hash.hash);
				rap_mark_retloc(&gsi, computed_hash);
			}

			bb = gsi_bb(gsi);
			gcc_assert(call_stmt == gsi_stmt(gsi));
		}
	}

	free_dominance_info(CDI_DOMINATORS);
	free_dominance_info(CDI_POST_DOMINATORS);
	loop_optimizer_finalize();

	return 0;
}

#define PASS_NAME rap_fptr
#define TODO_FLAGS_FINISH TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_remove_unused_locals | TODO_update_ssa | TODO_cleanup_cfg | TODO_rebuild_cgraph_edges | TODO_verify_flow
#include "gcc-generate-gimple-pass.h"
