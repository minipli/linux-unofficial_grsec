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

#define MIN_CHECK true
#define MAX_CHECK false

unsigned int call_count = 0;

tree get_size_overflow_type(struct visited *visited, const_gimple stmt, const_tree node)
{
	const_tree type;
	tree new_type;

	gcc_assert(node != NULL_TREE);

	type = TREE_TYPE(node);

	if (pointer_set_contains(visited->my_stmts, stmt))
		return TREE_TYPE(node);

	switch (TYPE_MODE(type)) {
	case QImode:
	case HImode:
		new_type = size_overflow_type_SI;
		break;
	case SImode:
		new_type = size_overflow_type_DI;
		break;
	case DImode:
		if (LONG_TYPE_SIZE == GET_MODE_BITSIZE(SImode))
			new_type = TYPE_UNSIGNED(type) ? unsigned_intDI_type_node : intDI_type_node;
		else
			new_type = size_overflow_type_TI;
		break;
	case TImode:
		gcc_assert(!TYPE_UNSIGNED(type));
		new_type = size_overflow_type_TI;
		break;
	default:
		debug_tree(node);
		error("%s: unsupported gcc configuration (%qE).", __func__, current_function_decl);
		gcc_unreachable();
	}

	if (TYPE_QUALS(type) != 0)
		return build_qualified_type(new_type, TYPE_QUALS(type));
	return new_type;
}

tree cast_to_new_size_overflow_type(struct visited *visited, gimple stmt, tree rhs, tree size_overflow_type, bool before)
{
	gimple_stmt_iterator gsi;
	gimple new_stmt;

	if (rhs == NULL_TREE)
		return NULL_TREE;

	gsi = gsi_for_stmt(stmt);
	new_stmt = build_cast_stmt(visited, size_overflow_type, rhs, CREATE_NEW_VAR, &gsi, before, false);
	if (gimple_assign_cast_p(new_stmt))
		gimple_assign_set_rhs_code(new_stmt, CONVERT_EXPR);
	pointer_set_insert(visited->my_stmts, new_stmt);

	return get_lhs(new_stmt);
}

tree create_assign(struct visited *visited, gimple oldstmt, tree rhs1, bool before)
{
	tree lhs, dst_type;
	gimple_stmt_iterator gsi;

	if (rhs1 == NULL_TREE) {
		debug_gimple_stmt(oldstmt);
		error("%s: rhs1 is NULL_TREE", __func__);
		gcc_unreachable();
	}

	switch (gimple_code(oldstmt)) {
	case GIMPLE_ASM:
		lhs = rhs1;
		break;
	case GIMPLE_CALL:
	case GIMPLE_ASSIGN:
		lhs = gimple_get_lhs(oldstmt);
		break;
	default:
		debug_gimple_stmt(oldstmt);
		gcc_unreachable();
	}

	gsi = gsi_for_stmt(oldstmt);
	pointer_set_insert(visited->stmts, oldstmt);
	if (lookup_stmt_eh_lp(oldstmt) != 0) {
		basic_block next_bb, cur_bb;
		const_edge e;

		gcc_assert(before == false);
		gcc_assert(stmt_can_throw_internal(oldstmt));
		gcc_assert(gimple_code(oldstmt) == GIMPLE_CALL);
		gcc_assert(!gsi_end_p(gsi));

		cur_bb = gimple_bb(oldstmt);
		next_bb = cur_bb->next_bb;
		e = find_edge(cur_bb, next_bb);
		gcc_assert(e != NULL);
		gcc_assert(e->flags & EDGE_FALLTHRU);

		gsi = gsi_after_labels(next_bb);
		gcc_assert(!gsi_end_p(gsi));

		before = true;
		oldstmt = gsi_stmt(gsi);
	}

	if (is_gimple_constant(rhs1) && TREE_CODE_CLASS(gimple_assign_rhs_code(oldstmt)) == tcc_comparison)
		dst_type = get_size_overflow_type(visited, oldstmt, rhs1);
	else
		dst_type = get_size_overflow_type(visited, oldstmt, lhs);

	if (is_gimple_constant(rhs1))
		return cast_a_tree(dst_type, rhs1);
	return cast_to_new_size_overflow_type(visited, oldstmt, rhs1, dst_type, before);
}

tree dup_assign(struct visited *visited, gassign *oldstmt, const_tree node, tree rhs1, tree rhs2, tree __unused rhs3)
{
	gassign *stmt;
	gimple_stmt_iterator gsi;
	tree size_overflow_type, new_var, lhs = gimple_assign_lhs(oldstmt);

	if (pointer_set_contains(visited->my_stmts, oldstmt))
		return lhs;

	if (gimple_num_ops(oldstmt) != 4 && rhs1 == NULL_TREE) {
		rhs1 = gimple_assign_rhs1(oldstmt);
		rhs1 = create_assign(visited, oldstmt, rhs1, BEFORE_STMT);
	}
	if (gimple_num_ops(oldstmt) == 3 && rhs2 == NULL_TREE) {
		rhs2 = gimple_assign_rhs2(oldstmt);
		rhs2 = create_assign(visited, oldstmt, rhs2, BEFORE_STMT);
	}

	stmt = as_a_gassign(gimple_copy(oldstmt));
	gimple_set_location(stmt, gimple_location(oldstmt));
	pointer_set_insert(visited->my_stmts, stmt);

	if (gimple_assign_rhs_code(oldstmt) == WIDEN_MULT_EXPR)
		gimple_assign_set_rhs_code(stmt, MULT_EXPR);

	size_overflow_type = get_size_overflow_type(visited, oldstmt, node);

	new_var = create_new_var(size_overflow_type);
	new_var = make_ssa_name(new_var, stmt);
	gimple_assign_set_lhs(stmt, new_var);

	if (rhs1 != NULL_TREE)
		gimple_assign_set_rhs1(stmt, rhs1);

	if (rhs2 != NULL_TREE)
		gimple_assign_set_rhs2(stmt, rhs2);
#if BUILDING_GCC_VERSION >= 4006
	if (rhs3 != NULL_TREE)
		gimple_assign_set_rhs3(stmt, rhs3);
#endif
	gimple_set_vuse(stmt, gimple_vuse(oldstmt));
	gimple_set_vdef(stmt, gimple_vdef(oldstmt));

	gsi = gsi_for_stmt(oldstmt);
	gsi_insert_after(&gsi, stmt, GSI_SAME_STMT);
	update_stmt(stmt);
	pointer_set_insert(visited->stmts, oldstmt);
	return gimple_assign_lhs(stmt);
}

static tree cast_parm_decl(struct visited *visited, tree phi_ssa_name, tree arg, tree size_overflow_type, basic_block bb)
{
	const_gimple assign;
	gimple_stmt_iterator gsi;
	basic_block first_bb;

	gcc_assert(SSA_NAME_IS_DEFAULT_DEF(arg));

	if (bb->index == 0) {
		first_bb = split_block_after_labels(ENTRY_BLOCK_PTR_FOR_FN(cfun))->dest;
		gcc_assert(dom_info_available_p(CDI_DOMINATORS));
		set_immediate_dominator(CDI_DOMINATORS, first_bb, ENTRY_BLOCK_PTR_FOR_FN(cfun));
		bb = first_bb;
	}

	gsi = gsi_after_labels(bb);
	assign = build_cast_stmt(visited, size_overflow_type, arg, phi_ssa_name, &gsi, BEFORE_STMT, false);
	pointer_set_insert(visited->my_stmts, assign);
	return get_lhs(assign);
}

static tree use_phi_ssa_name(struct visited *visited, tree ssa_name_var, tree new_arg)
{
	gimple_stmt_iterator gsi;
	const_gimple assign;
	gimple def_stmt = get_def_stmt(new_arg);

	if (gimple_code(def_stmt) == GIMPLE_PHI) {
		gsi = gsi_after_labels(gimple_bb(def_stmt));
		assign = build_cast_stmt(visited, TREE_TYPE(new_arg), new_arg, ssa_name_var, &gsi, BEFORE_STMT, true);
	} else {
		gsi = gsi_for_stmt(def_stmt);
		assign = build_cast_stmt(visited, TREE_TYPE(new_arg), new_arg, ssa_name_var, &gsi, AFTER_STMT, true);
	}

	pointer_set_insert(visited->my_stmts, assign);
	return get_lhs(assign);
}

static tree cast_visited_phi_arg(struct visited *visited, tree ssa_name_var, tree arg, tree size_overflow_type)
{
	basic_block bb;
	gimple_stmt_iterator gsi;
	const_gimple def_stmt;
	const_gimple assign;

	def_stmt = get_def_stmt(arg);
	bb = gimple_bb(def_stmt);
	gcc_assert(bb->index != 0);
	gsi = gsi_after_labels(bb);

	assign = build_cast_stmt(visited, size_overflow_type, arg, ssa_name_var, &gsi, BEFORE_STMT, false);
	pointer_set_insert(visited->my_stmts, assign);
	return get_lhs(assign);
}

static tree create_new_phi_arg(struct visited *visited, tree ssa_name_var, tree new_arg, gphi *oldstmt, unsigned int i)
{
	tree size_overflow_type;
	tree arg;
	const_gimple def_stmt;

	if (new_arg != NULL_TREE && is_gimple_constant(new_arg))
		return new_arg;

	arg = gimple_phi_arg_def(oldstmt, i);
	def_stmt = get_def_stmt(arg);
	gcc_assert(def_stmt != NULL);
	size_overflow_type = get_size_overflow_type(visited, oldstmt, arg);

	switch (gimple_code(def_stmt)) {
	case GIMPLE_PHI:
		return cast_visited_phi_arg(visited, ssa_name_var, arg, size_overflow_type);
	case GIMPLE_NOP: {
		basic_block bb;

		bb = gimple_phi_arg_edge(oldstmt, i)->src;
		return cast_parm_decl(visited, ssa_name_var, arg, size_overflow_type, bb);
	}
	case GIMPLE_ASM: {
		gimple_stmt_iterator gsi;
		const_gimple assign;
		gimple stmt = get_def_stmt(arg);

		gsi = gsi_for_stmt(stmt);
		assign = build_cast_stmt(visited, size_overflow_type, arg, ssa_name_var, &gsi, AFTER_STMT, false);
		pointer_set_insert(visited->my_stmts, assign);
		return get_lhs(assign);
	}
	default:
		gcc_assert(new_arg != NULL_TREE);
		gcc_assert(types_compatible_p(TREE_TYPE(new_arg), size_overflow_type));
		return use_phi_ssa_name(visited, ssa_name_var, new_arg);
	}
}

static gphi *overflow_create_phi_node(struct visited *visited, gphi *oldstmt, tree result)
{
	basic_block bb;
	gphi *phi;
	gimple_seq seq;
	gimple_stmt_iterator gsi = gsi_for_stmt(oldstmt);

	bb = gsi_bb(gsi);

	if (result == NULL_TREE) {
		tree old_result = gimple_phi_result(oldstmt);
		tree size_overflow_type = get_size_overflow_type(visited, oldstmt, old_result);

		result = create_new_var(size_overflow_type);
	}

	phi = as_a_gphi(create_phi_node(result, bb));
	gimple_phi_set_result(phi, make_ssa_name(result, phi));
	seq = phi_nodes(bb);
	gsi = gsi_last(seq);
	gsi_remove(&gsi, false);

	gsi = gsi_for_stmt(oldstmt);
	gsi_insert_after(&gsi, phi, GSI_NEW_STMT);
	gimple_set_bb(phi, bb);
	return phi;
}

#if BUILDING_GCC_VERSION <= 4007
static tree create_new_phi_node(struct visited *visited, VEC(tree, heap) **args, tree ssa_name_var, gimple oldstmt)
#else
static tree create_new_phi_node(struct visited *visited, vec<tree, va_heap, vl_embed> *&args, tree ssa_name_var, gphi *oldstmt)
#endif
{
	gphi *new_phi;
	unsigned int i;
	tree arg, result;
	location_t loc = gimple_location(oldstmt);

#if BUILDING_GCC_VERSION <= 4007
	gcc_assert(!VEC_empty(tree, *args));
#else
	gcc_assert(!args->is_empty());
#endif

	new_phi = overflow_create_phi_node(visited, oldstmt, ssa_name_var);
	result = gimple_phi_result(new_phi);
	ssa_name_var = SSA_NAME_VAR(result);

#if BUILDING_GCC_VERSION <= 4007
	FOR_EACH_VEC_ELT(tree, *args, i, arg) {
#else
	FOR_EACH_VEC_SAFE_ELT(args, i, arg) {
#endif
		arg = create_new_phi_arg(visited, ssa_name_var, arg, oldstmt, i);
		add_phi_arg(new_phi, arg, gimple_phi_arg_edge(oldstmt, i), loc);
	}

#if BUILDING_GCC_VERSION <= 4007
	VEC_free(tree, heap, *args);
#else
	vec_free(args);
#endif
	update_stmt(new_phi);
	pointer_set_insert(visited->my_stmts, new_phi);
	return result;
}

static tree handle_phi(interesting_stmts_t expand_from, tree orig_result)
{
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, heap) *args = NULL;
#else
	vec<tree, va_heap, vl_embed> *args = NULL;
#endif
	unsigned int i, len;
	tree ssa_name_var = NULL_TREE;
	gphi *oldstmt = as_a_gphi(get_def_stmt(orig_result));

	len = gimple_phi_num_args(oldstmt);
	pointer_set_insert(expand_from->visited->stmts, oldstmt);
	for (i = 0; i < len; i++) {
		tree arg, new_arg;

		arg = gimple_phi_arg_def(oldstmt, i);
		new_arg = expand(expand_from, arg);

		if (ssa_name_var == NULL_TREE && new_arg != NULL_TREE)
			ssa_name_var = SSA_NAME_VAR(new_arg);

		if (is_gimple_constant(arg)) {
			tree size_overflow_type = get_size_overflow_type(expand_from->visited, oldstmt, arg);

			new_arg = cast_a_tree(size_overflow_type, arg);
		}

#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(tree, heap, args, new_arg);
#else
		vec_safe_push(args, new_arg);
#endif
	}

#if BUILDING_GCC_VERSION <= 4007
	return create_new_phi_node(expand_from->visited, &args, ssa_name_var, oldstmt);
#else
	return create_new_phi_node(expand_from->visited, args, ssa_name_var, oldstmt);
#endif
}

static tree create_cast_assign(struct visited *visited, gassign *stmt)
{
	tree rhs1 = gimple_assign_rhs1(stmt);
	tree lhs = gimple_assign_lhs(stmt);
	const_tree rhs1_type = TREE_TYPE(rhs1);
	const_tree lhs_type = TREE_TYPE(lhs);

	if (TYPE_UNSIGNED(rhs1_type) == TYPE_UNSIGNED(lhs_type))
		return create_assign(visited, stmt, lhs, AFTER_STMT);

	return create_assign(visited, stmt, rhs1, AFTER_STMT);
}

static bool skip_lhs_cast_check(struct visited *visited, const gassign *stmt)
{
	const_tree rhs = gimple_assign_rhs1(stmt);
	const_gimple def_stmt = get_def_stmt(rhs);

	// 3.8.2 kernel/futex_compat.c compat_exit_robust_list(): get_user() 64 ulong -> int (compat_long_t), int max
	if (gimple_code(def_stmt) == GIMPLE_ASM)
		return true;

	if (is_const_plus_unsigned_signed_truncation(rhs)) {
		pointer_set_insert(visited->no_cast_check, stmt);
		return true;
	}

	return false;
}

static tree create_string_param(tree string)
{
	return build1(ADDR_EXPR, ptr_type_node, string);
}

static void insert_cond(basic_block cond_bb, tree arg, enum tree_code cond_code, tree type_value)
{
	gcond *cond_stmt;
	gimple_stmt_iterator gsi = gsi_last_bb(cond_bb);

	cond_stmt = gimple_build_cond(cond_code, arg, type_value, NULL_TREE, NULL_TREE);
	gsi_insert_after(&gsi, cond_stmt, GSI_CONTINUE_LINKING);
	update_stmt(cond_stmt);
}

static void insert_cond_result(interesting_stmts_t expand_from, basic_block bb_true, const_gimple stmt, const_tree arg, bool min)
{
	gcall *func_stmt;
	const_gimple def_stmt;
	const_tree loc_line;
	tree loc_file, ssa_name, current_func;
	expanded_location xloc;
	char *ssa_name_buf;
	int len;
	struct cgraph_edge *edge;
	struct cgraph_node *report_node;
	int frequency;
	gimple_stmt_iterator gsi = gsi_start_bb(bb_true);

	def_stmt = get_def_stmt(arg);
	if (gimple_has_location(def_stmt))
		xloc = expand_location(gimple_location(def_stmt));
	else if (gimple_has_location(stmt))
		xloc = expand_location(gimple_location(stmt));
	else
		xloc = expand_location(DECL_SOURCE_LOCATION(current_function_decl));

	loc_line = build_int_cstu(unsigned_type_node, xloc.line);

	loc_file = build_const_char_string(strlen(xloc.file) + 1, xloc.file);
	loc_file = create_string_param(loc_file);

	current_func = build_const_char_string(DECL_NAME_LENGTH(current_function_decl) + 1, DECL_NAME_POINTER(current_function_decl));
	current_func = create_string_param(current_func);

	gcc_assert(DECL_NAME(SSA_NAME_VAR(arg)) != NULL);
	call_count++;
	len = asprintf(&ssa_name_buf, "%s_%u %s, count: %u, decl: %s; num: %u; context: %s;\n", DECL_NAME_POINTER(SSA_NAME_VAR(arg)), SSA_NAME_VERSION(arg), min ? "min" : "max", call_count, expand_from->next_node->decl_name, expand_from->next_node->num, expand_from->next_node->context);
	gcc_assert(len > 0);
	ssa_name = build_const_char_string(len + 1, ssa_name_buf);
	free(ssa_name_buf);
	ssa_name = create_string_param(ssa_name);

	// void report_size_overflow(const char *file, unsigned int line, const char *func, const char *ssa_name)
	func_stmt = as_a_gcall(gimple_build_call(report_size_overflow_decl, 4, loc_file, loc_line, current_func, ssa_name));
	gsi_insert_after(&gsi, func_stmt, GSI_CONTINUE_LINKING);

	report_node = cgraph_get_create_node(report_size_overflow_decl);
	gcc_assert(report_node);
	frequency = compute_call_stmt_bb_frequency(current_function_decl, bb_true);

	edge = cgraph_create_edge(get_cnode(current_function_decl), report_node, func_stmt, bb_true->count, frequency, bb_true->loop_depth);
	gcc_assert(edge != NULL);
}

static void insert_check_size_overflow(interesting_stmts_t expand_from, gimple stmt, enum tree_code cond_code, tree arg, tree type_value, bool before, bool min)
{
	basic_block cond_bb, join_bb, bb_true;
	edge e;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);

	cond_bb = gimple_bb(stmt);
	if (before)
		gsi_prev(&gsi);
	if (gsi_end_p(gsi))
		e = split_block_after_labels(cond_bb);
	else
		e = split_block(cond_bb, gsi_stmt(gsi));
	cond_bb = e->src;
	join_bb = e->dest;
	e->flags = EDGE_FALSE_VALUE;
	e->probability = REG_BR_PROB_BASE;

	bb_true = create_empty_bb(cond_bb);
	make_edge(cond_bb, bb_true, EDGE_TRUE_VALUE);
	make_edge(cond_bb, join_bb, EDGE_FALSE_VALUE);
	make_edge(bb_true, join_bb, EDGE_FALLTHRU);

	gcc_assert(dom_info_available_p(CDI_DOMINATORS));
	set_immediate_dominator(CDI_DOMINATORS, bb_true, cond_bb);
	set_immediate_dominator(CDI_DOMINATORS, join_bb, cond_bb);

	if (current_loops != NULL) {
		gcc_assert(cond_bb->loop_father == join_bb->loop_father);
		add_bb_to_loop(bb_true, cond_bb->loop_father);
	}

	insert_cond(cond_bb, arg, cond_code, type_value);
	insert_cond_result(expand_from, bb_true, stmt, arg, min);

//	print_the_code_insertions(stmt);
}

void check_size_overflow(interesting_stmts_t expand_from, gimple stmt, tree size_overflow_type, tree cast_rhs, tree rhs, bool before)
{
	const_tree rhs_type = TREE_TYPE(rhs);
	tree cast_rhs_type, type_max_type, type_min_type, type_max, type_min;

	if (pointer_set_contains(expand_from->visited->no_cast_check, stmt))
		return;

	gcc_assert(rhs_type != NULL_TREE);
	if (TREE_CODE(rhs_type) == POINTER_TYPE)
		return;

	gcc_assert(TREE_CODE(rhs_type) == INTEGER_TYPE || TREE_CODE(rhs_type) == ENUMERAL_TYPE);

	if (is_gimple_assign(stmt) && neg_short_add_intentional_overflow(as_a_gassign(stmt)))
		return;

	type_max = cast_a_tree(size_overflow_type, TYPE_MAX_VALUE(rhs_type));
	// typemax (-1) < typemin (0)
	if (TREE_OVERFLOW(type_max))
		return;

	type_min = cast_a_tree(size_overflow_type, TYPE_MIN_VALUE(rhs_type));

	cast_rhs_type = TREE_TYPE(cast_rhs);
	type_max_type = TREE_TYPE(type_max);
	gcc_assert(types_compatible_p(cast_rhs_type, type_max_type));

	insert_check_size_overflow(expand_from, stmt, GT_EXPR, cast_rhs, type_max, before, MAX_CHECK);

	// special case: get_size_overflow_type(), 32, u64->s
	if (LONG_TYPE_SIZE == GET_MODE_BITSIZE(SImode) && TYPE_UNSIGNED(size_overflow_type) && !TYPE_UNSIGNED(rhs_type))
		return;

	type_min_type = TREE_TYPE(type_min);
	gcc_assert(types_compatible_p(type_max_type, type_min_type));
	insert_check_size_overflow(expand_from, stmt, LT_EXPR, cast_rhs, type_min, before, MIN_CHECK);
}

static tree get_my_stmt_lhs(struct visited *visited, gimple stmt)
{
	gimple_stmt_iterator gsi;
	gimple next_stmt = NULL;

	gsi = gsi_for_stmt(stmt);

	do {
		gsi_next(&gsi);
		next_stmt = gsi_stmt(gsi);

		if (gimple_code(stmt) == GIMPLE_PHI && !pointer_set_contains(visited->my_stmts, next_stmt))
			return NULL_TREE;

		if (pointer_set_contains(visited->my_stmts, next_stmt) && !pointer_set_contains(visited->skip_expr_casts, next_stmt))
			break;

		gcc_assert(pointer_set_contains(visited->my_stmts, next_stmt));
	} while (!gsi_end_p(gsi));

	gcc_assert(next_stmt);
	return get_lhs(next_stmt);
}

/* When the result of the negation is cast to a signed type then move
 * the size_overflow cast check before negation.
 * ssa:
 * unsigned _588
 * _588 = _587 >> 12;
 * _589 = -_588;
 * _590 = (long int) _589;
 */
static bool handle_unsigned_neg_or_bit_not(interesting_stmts_t expand_from, const gassign *stmt)
{
	gimple def_neg_stmt, neg_stmt;
	tree lhs, new_neg_rhs;
	const_tree rhs, neg_rhs;
	enum tree_code rhs_code;

	rhs = gimple_assign_rhs1(stmt);
	lhs = gimple_assign_lhs(stmt);
	if (TYPE_UNSIGNED(TREE_TYPE(lhs)) || !TYPE_UNSIGNED(TREE_TYPE(rhs)))
		return false;

	neg_stmt = get_def_stmt(rhs);
	if (!neg_stmt || !is_gimple_assign(neg_stmt))
		return false;

	rhs_code = gimple_assign_rhs_code(neg_stmt);
	if (rhs_code != BIT_NOT_EXPR && rhs_code != NEGATE_EXPR)
		return false;

	neg_rhs = gimple_assign_rhs1(neg_stmt);
	def_neg_stmt = get_def_stmt(neg_rhs);
	if (!def_neg_stmt)
		return false;

	new_neg_rhs = get_my_stmt_lhs(expand_from->visited, def_neg_stmt);
	check_size_overflow(expand_from, neg_stmt, TREE_TYPE(new_neg_rhs), new_neg_rhs, lhs, BEFORE_STMT);
	pointer_set_insert(expand_from->visited->no_cast_check, stmt);
	return true;
}

static tree create_cast_overflow_check(interesting_stmts_t expand_from, tree new_rhs1, gassign *stmt)
{
	bool cast_lhs, cast_rhs;
	tree lhs = gimple_assign_lhs(stmt);
	tree rhs = gimple_assign_rhs1(stmt);
	const_tree lhs_type = TREE_TYPE(lhs);
	const_tree rhs_type = TREE_TYPE(rhs);
	enum machine_mode lhs_mode = TYPE_MODE(lhs_type);
	enum machine_mode rhs_mode = TYPE_MODE(rhs_type);
	unsigned int lhs_size = GET_MODE_BITSIZE(lhs_mode);
	unsigned int rhs_size = GET_MODE_BITSIZE(rhs_mode);

	static bool check_lhs[3][4] = {
		// ss    su     us     uu
		{ false, true,  true,  false }, // lhs > rhs
		{ false, false, false, false }, // lhs = rhs
		{ true,  true,  true,  true  }, // lhs < rhs
	};

	static bool check_rhs[3][4] = {
		// ss    su     us     uu
		{ true,  false, true,  true  }, // lhs > rhs
		{ true,  false, true,  true  }, // lhs = rhs
		{ true,  false, true,  true  }, // lhs < rhs
	};

	if (handle_unsigned_neg_or_bit_not(expand_from, stmt))
		return dup_assign(expand_from->visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);

	// skip lhs check on HI -> QI cast
	if (rhs_mode == HImode && lhs_mode == QImode) {
		pointer_set_insert(expand_from->visited->no_cast_check, stmt);
		return dup_assign(expand_from->visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);
	}

	// skip lhs check on signed SI -> HI cast or signed SI -> QI cast
	if (rhs_mode == SImode && !TYPE_UNSIGNED(rhs_type) && (lhs_mode == HImode || lhs_mode == QImode))
		return create_assign(expand_from->visited, stmt, lhs, AFTER_STMT);

	if (lhs_size > rhs_size) {
		cast_lhs = check_lhs[0][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
		cast_rhs = check_rhs[0][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
	} else if (lhs_size == rhs_size) {
		cast_lhs = check_lhs[1][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
		cast_rhs = check_rhs[1][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
	} else {
		cast_lhs = check_lhs[2][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
		cast_rhs = check_rhs[2][TYPE_UNSIGNED(rhs_type) + 2 * TYPE_UNSIGNED(lhs_type)];
	}

	if (!cast_lhs && !cast_rhs)
		return dup_assign(expand_from->visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);

	if (cast_lhs && !skip_lhs_cast_check(expand_from->visited, stmt))
		check_size_overflow(expand_from, stmt, TREE_TYPE(new_rhs1), new_rhs1, lhs, BEFORE_STMT);

	if (cast_rhs)
		check_size_overflow(expand_from, stmt, TREE_TYPE(new_rhs1), new_rhs1, rhs, BEFORE_STMT);

	return dup_assign(expand_from->visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);
}

static tree handle_unary_rhs(interesting_stmts_t expand_from, gassign *stmt)
{
	enum tree_code rhs_code;
	tree rhs1, new_rhs1, lhs = gimple_assign_lhs(stmt);

	if (pointer_set_contains(expand_from->visited->my_stmts, stmt))
		return lhs;

	rhs1 = gimple_assign_rhs1(stmt);
	if (TREE_CODE(TREE_TYPE(rhs1)) == POINTER_TYPE)
		return create_assign(expand_from->visited, stmt, lhs, AFTER_STMT);

	new_rhs1 = expand(expand_from, rhs1);

	if (new_rhs1 == NULL_TREE)
		return create_cast_assign(expand_from->visited, stmt);

	if (pointer_set_contains(expand_from->visited->no_cast_check, stmt))
		return dup_assign(expand_from->visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);

#if BUILDING_GCC_VERSION >= 5000
	if (short_or_neg_const_ushort(stmt)) {
		pointer_set_insert(expand_from->visited->no_cast_check, stmt);
		return dup_assign(expand_from->visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);
	}
#endif

	rhs_code = gimple_assign_rhs_code(stmt);
	if (rhs_code == BIT_NOT_EXPR || rhs_code == NEGATE_EXPR) {
		tree size_overflow_type = get_size_overflow_type(expand_from->visited, stmt, rhs1);

		new_rhs1 = cast_to_new_size_overflow_type(expand_from->visited, stmt, new_rhs1, size_overflow_type, BEFORE_STMT);
		check_size_overflow(expand_from, stmt, size_overflow_type, new_rhs1, rhs1, BEFORE_STMT);
		return create_assign(expand_from->visited, stmt, lhs, AFTER_STMT);
	}

	if (!gimple_assign_cast_p(stmt))
		return dup_assign(expand_from->visited, stmt, lhs, new_rhs1, NULL_TREE, NULL_TREE);

	return create_cast_overflow_check(expand_from, new_rhs1, stmt);
}

static tree handle_unary_ops(interesting_stmts_t expand_from, gassign *stmt)
{
	tree rhs1, lhs = gimple_assign_lhs(stmt);
	gimple def_stmt = get_def_stmt(lhs);

	gcc_assert(gimple_code(def_stmt) != GIMPLE_NOP);
	rhs1 = gimple_assign_rhs1(def_stmt);

	if (is_gimple_constant(rhs1))
		return create_assign(expand_from->visited, def_stmt, lhs, AFTER_STMT);

	switch (TREE_CODE(rhs1)) {
	case SSA_NAME: {
		tree ret = handle_unary_rhs(expand_from, as_a_gassign(def_stmt));

		if (gimple_assign_cast_p(stmt))
			unsigned_signed_cast_intentional_overflow(expand_from->visited, stmt);
		return ret;
	}
	case ARRAY_REF:
	case BIT_FIELD_REF:
	case ADDR_EXPR:
	case COMPONENT_REF:
	case INDIRECT_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case TARGET_MEM_REF:
	case VIEW_CONVERT_EXPR:
		return create_assign(expand_from->visited, def_stmt, lhs, AFTER_STMT);
	case PARM_DECL:
	case VAR_DECL:
		return create_assign(expand_from->visited, stmt, lhs, AFTER_STMT);

	default:
		debug_gimple_stmt(def_stmt);
		debug_tree(rhs1);
		gcc_unreachable();
	}
}

static void __unused print_the_code_insertions(const_gimple stmt)
{
	location_t loc = gimple_location(stmt);

	inform(loc, "Integer size_overflow check applied here.");
}

static bool is_from_cast(const_tree node)
{
	gimple def_stmt = get_def_stmt(node);

	if (!def_stmt)
		return false;

	if (gimple_assign_cast_p(def_stmt))
		return true;

	return false;
}

// Skip duplication when there is a minus expr and the type of rhs1 or rhs2 is a pointer_type.
static bool is_ptr_diff(gassign *stmt)
{
	const_tree rhs1, rhs2, ptr1_rhs, ptr2_rhs;

	if (gimple_assign_rhs_code(stmt) != MINUS_EXPR)
		return false;

	rhs1 = gimple_assign_rhs1(stmt);
	if (!is_from_cast(rhs1))
		return false;

	rhs2 = gimple_assign_rhs2(stmt);
	if (!is_from_cast(rhs2))
		return false;

	ptr1_rhs = gimple_assign_rhs1(get_def_stmt(rhs1));
	ptr2_rhs = gimple_assign_rhs1(get_def_stmt(rhs2));

	if (TREE_CODE(TREE_TYPE(ptr1_rhs)) != POINTER_TYPE && TREE_CODE(TREE_TYPE(ptr2_rhs)) != POINTER_TYPE)
		return false;

	return true;
}

static tree handle_comparison_code_class(interesting_stmts_t expand_from, gassign *stmt, tree new_rhs1, tree new_rhs2)
{
	tree rhs1, rhs2, lhs;

	rhs1 = gimple_assign_rhs1(stmt);
	if (!is_gimple_constant(rhs1) && new_rhs1 != NULL_TREE)
		check_size_overflow(expand_from, stmt, TREE_TYPE(new_rhs1), new_rhs1, rhs1, BEFORE_STMT);

	lhs = gimple_assign_lhs(stmt);
	if (new_rhs2 == NULL_TREE)
		return create_assign(expand_from->visited, stmt, lhs, AFTER_STMT);

	rhs2 = gimple_assign_rhs2(stmt);
	if (!is_gimple_constant(rhs2))
		check_size_overflow(expand_from, stmt, TREE_TYPE(new_rhs2), new_rhs2, rhs2, BEFORE_STMT);
	return create_assign(expand_from->visited, stmt, lhs, AFTER_STMT);
}

static tree handle_binary_ops(interesting_stmts_t expand_from, tree lhs)
{
	enum intentional_overflow_type res;
	tree rhs1, rhs2, new_lhs;
	gassign *def_stmt = as_a_gassign(get_def_stmt(lhs));
	tree new_rhs1 = NULL_TREE;
	tree new_rhs2 = NULL_TREE;

	if (is_ptr_diff(def_stmt))
		return create_assign(expand_from->visited, def_stmt, lhs, AFTER_STMT);

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);

	/* no DImode/TImode division in the 32/64 bit kernel */
	switch (gimple_assign_rhs_code(def_stmt)) {
	case RDIV_EXPR:
	case TRUNC_DIV_EXPR:
	case CEIL_DIV_EXPR:
	case FLOOR_DIV_EXPR:
	case ROUND_DIV_EXPR:
	case TRUNC_MOD_EXPR:
	case CEIL_MOD_EXPR:
	case FLOOR_MOD_EXPR:
	case ROUND_MOD_EXPR:
	case EXACT_DIV_EXPR:
	case POINTER_PLUS_EXPR:
	case BIT_AND_EXPR:
		return create_assign(expand_from->visited, def_stmt, lhs, AFTER_STMT);
	default:
		break;
	}

	new_lhs = handle_integer_truncation(expand_from, lhs);
	if (new_lhs != NULL_TREE)
		return new_lhs;

	if (TREE_CODE(rhs1) == SSA_NAME)
		new_rhs1 = expand(expand_from, rhs1);
	if (TREE_CODE(rhs2) == SSA_NAME)
		new_rhs2 = expand(expand_from, rhs2);

	res = add_mul_intentional_overflow(def_stmt);
	if (res != NO_INTENTIONAL_OVERFLOW) {
		new_lhs = dup_assign(expand_from->visited, def_stmt, lhs, new_rhs1, new_rhs2, NULL_TREE);
		insert_cast_expr(expand_from->visited, as_a_gassign(get_def_stmt(new_lhs)), res);
		return new_lhs;
	}

	if (skip_expr_on_double_type(def_stmt)) {
		new_lhs = dup_assign(expand_from->visited, def_stmt, lhs, new_rhs1, new_rhs2, NULL_TREE);
		insert_cast_expr(expand_from->visited, as_a_gassign(get_def_stmt(new_lhs)), NO_INTENTIONAL_OVERFLOW);
		return new_lhs;
	}

	if (is_a_neg_overflow(def_stmt, rhs2))
		return handle_intentional_overflow(expand_from, true, def_stmt, new_rhs1, NULL_TREE);
	if (is_a_neg_overflow(def_stmt, rhs1))
		return handle_intentional_overflow(expand_from, true, def_stmt, new_rhs2, new_rhs2);


	if (is_a_constant_overflow(def_stmt, rhs2))
		return handle_intentional_overflow(expand_from, !is_a_cast_and_const_overflow(rhs1), def_stmt, new_rhs1, NULL_TREE);
	if (is_a_constant_overflow(def_stmt, rhs1))
		return handle_intentional_overflow(expand_from, !is_a_cast_and_const_overflow(rhs2), def_stmt, new_rhs2, new_rhs2);

	// the const is between 0 and (signed) MAX
	if (is_gimple_constant(rhs1))
		new_rhs1 = create_assign(expand_from->visited, def_stmt, rhs1, BEFORE_STMT);
	if (is_gimple_constant(rhs2))
		new_rhs2 = create_assign(expand_from->visited, def_stmt, rhs2, BEFORE_STMT);

	if (TREE_CODE_CLASS(gimple_assign_rhs_code(def_stmt)) == tcc_comparison)
		return handle_comparison_code_class(expand_from, def_stmt, new_rhs1, new_rhs2);

	if (uconst_neg_intentional_overflow(def_stmt)) {
		inform(gimple_location(def_stmt), "%s: gcc intentional overflow", __func__);
		gcc_unreachable();
	}

	return dup_assign(expand_from->visited, def_stmt, lhs, new_rhs1, new_rhs2, NULL_TREE);
}

#if BUILDING_GCC_VERSION >= 4006
static tree get_new_rhs(interesting_stmts_t expand_from, tree size_overflow_type, tree rhs)
{
	if (is_gimple_constant(rhs))
		return cast_a_tree(size_overflow_type, rhs);
	if (TREE_CODE(rhs) != SSA_NAME)
		return NULL_TREE;
	return expand(expand_from, rhs);
}

static tree handle_ternary_ops(interesting_stmts_t expand_from, tree lhs)
{
	tree rhs1, rhs2, rhs3, new_rhs1, new_rhs2, new_rhs3, size_overflow_type;
	gassign *def_stmt = as_a_gassign(get_def_stmt(lhs));

	size_overflow_type = get_size_overflow_type(expand_from->visited, def_stmt, lhs);

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	rhs3 = gimple_assign_rhs3(def_stmt);
	new_rhs1 = get_new_rhs(expand_from, size_overflow_type, rhs1);
	new_rhs2 = get_new_rhs(expand_from, size_overflow_type, rhs2);
	new_rhs3 = get_new_rhs(expand_from, size_overflow_type, rhs3);

	return dup_assign(expand_from->visited, def_stmt, lhs, new_rhs1, new_rhs2, new_rhs3);
}
#endif

static tree expand_visited(struct visited *visited, gimple def_stmt)
{
	gimple_stmt_iterator gsi;
	enum gimple_code code = gimple_code(def_stmt);

	if (code == GIMPLE_ASM)
		return NULL_TREE;

	gsi = gsi_for_stmt(def_stmt);
	gsi_next(&gsi);

	if (gimple_code(def_stmt) == GIMPLE_PHI && gsi_end_p(gsi))
		return NULL_TREE;
	return get_my_stmt_lhs(visited, def_stmt);
}

tree expand(interesting_stmts_t expand_from, tree lhs)
{
	gimple def_stmt;

	def_stmt = get_def_stmt(lhs);

	if (!def_stmt || gimple_code(def_stmt) == GIMPLE_NOP)
		return NULL_TREE;

	if (pointer_set_contains(expand_from->visited->my_stmts, def_stmt))
		return lhs;

	if (pointer_set_contains(expand_from->visited->stmts, def_stmt))
		return expand_visited(expand_from->visited, def_stmt);

	if (is_gimple_constant(lhs))
		return NULL_TREE;
	if (skip_types(lhs))
		return NULL_TREE;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_PHI:
		return handle_phi(expand_from, lhs);
	case GIMPLE_CALL:
	case GIMPLE_ASM:
		if (is_size_overflow_asm(def_stmt))
			return expand(expand_from, get_size_overflow_asm_input(as_a_gasm(def_stmt)));
		return create_assign(expand_from->visited, def_stmt, lhs, AFTER_STMT);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return handle_unary_ops(expand_from, as_a_gassign(def_stmt));
		case 3:
			return handle_binary_ops(expand_from, lhs);
#if BUILDING_GCC_VERSION >= 4006
		case 4:
			return handle_ternary_ops(expand_from, lhs);
#endif
		}
	default:
		debug_gimple_stmt(def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}
