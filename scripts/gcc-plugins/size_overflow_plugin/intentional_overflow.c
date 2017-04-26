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

static enum intentional_mark walk_use_def(gimple_set *visited, const_tree lhs);

static const char *get_asm_string(const gasm *stmt)
{
	if (stmt)
		return gimple_asm_string(stmt);
	return NULL;
}

tree get_size_overflow_asm_input(const gasm *stmt)
{
	gcc_assert(gimple_asm_ninputs(stmt) != 0);
	return TREE_VALUE(gimple_asm_input_op(stmt, 0));
}

bool is_size_overflow_insert_check_asm(const gasm *stmt)
{
	const char *str;

	if (!is_size_overflow_asm(stmt))
		return false;

	str = get_asm_string(stmt);
	if (!str)
		return false;
	return !strncmp(str, OK_ASM_STR, sizeof(OK_ASM_STR) - 1);
}

bool is_size_overflow_asm(const_gimple stmt)
{
	const char *str;

	if (!stmt)
		return false;
	if (gimple_code(stmt) != GIMPLE_ASM)
		return false;

	str = get_asm_string(as_a_const_gasm(stmt));
	if (!str)
		return false;
	return !strncmp(str, SO_ASM_STR, sizeof(SO_ASM_STR) - 1);
}

static bool is_size_overflow_intentional_asm_turn_off(const gasm *stmt)
{
	const char *str;

	if (!is_size_overflow_asm(stmt))
		return false;

	str = get_asm_string(stmt);
	if (!str)
		return false;
	return !strncmp(str, TURN_OFF_ASM_STR, sizeof(TURN_OFF_ASM_STR) - 1);
}

static bool is_size_overflow_intentional_asm_end(const gasm *stmt)
{
	const char *str;

	if (!is_size_overflow_asm(stmt))
		return false;

	str = get_asm_string(stmt);
	if (!str)
		return false;
	return !strncmp(str, END_INTENTIONAL_ASM_STR, sizeof(END_INTENTIONAL_ASM_STR) - 1);
}

/* Get the param of the intentional_overflow attribute.
 *   * 0: MARK_END_INTENTIONAL
 *   * 1..MAX_PARAM: MARK_YES
 *   * -1: MARK_TURN_OFF
 */
static tree get_attribute_param(const_tree decl)
{
	const_tree attr;

	if (decl == NULL_TREE)
		return NULL_TREE;

	attr = get_attribute("intentional_overflow", decl);
	if (attr)
		return TREE_VALUE(attr);
	return NULL_TREE;
}

// MARK_TURN_OFF
static bool is_turn_off_intentional_attr(const_tree decl)
{
	const_tree param_head;

	param_head = get_attribute_param(decl);
	if (param_head == NULL_TREE)
		return false;

	if (tree_to_shwi(TREE_VALUE(param_head)) == -1)
		return true;
	return false;
}

// MARK_END_INTENTIONAL
static bool is_end_intentional_intentional_attr(const_tree decl)
{
	const_tree param_head;

	param_head = get_attribute_param(decl);
	if (param_head == NULL_TREE)
		return false;

	if (tree_to_shwi(TREE_VALUE(param_head)) == 0)
		return true;
	return false;
}

// MARK_YES
static bool is_yes_intentional_attr(const_tree decl, unsigned int argnum)
{
	tree param, param_head;

	if (argnum == 0)
		return false;

	param_head = get_attribute_param(decl);
	for (param = param_head; param; param = TREE_CHAIN(param)) {
		int argval = tree_to_shwi(TREE_VALUE(param));

		if (argval <= 0)
			continue;
		if (argnum == (unsigned int)argval)
			return true;
	}
	return false;
}

static void print_missing_intentional(enum intentional_mark callee_attr, enum intentional_mark caller_attr, tree decl, unsigned int argnum)
{
	const struct size_overflow_hash *hash;
	struct fn_raw_data raw_data;
//	location_t loc;

	if (caller_attr == MARK_NO || caller_attr == MARK_END_INTENTIONAL || caller_attr == MARK_TURN_OFF)
		return;

	if (callee_attr == MARK_END_INTENTIONAL || callee_attr == MARK_YES)
		return;

	initialize_raw_data(&raw_data);
	raw_data.decl = decl;
	raw_data.num = argnum;
	hash = get_size_overflow_hash_entry_tree(&raw_data, SIZE_OVERFLOW);
	if (!hash)
		return;

// !!!
//	loc = DECL_SOURCE_LOCATION(decl);
//	inform(loc, "The intentional_overflow attribute is missing from +%s+%u+", DECL_NAME_POINTER(decl), argnum);
}

// Get the field decl of a component ref for intentional_overflow checking
static const_tree search_field_decl(const_tree comp_ref)
{
	const_tree field = NULL_TREE;
	unsigned int i, len = TREE_OPERAND_LENGTH(comp_ref);

	for (i = 0; i < len; i++) {
		field = TREE_OPERAND(comp_ref, i);
		if (TREE_CODE(field) == FIELD_DECL)
			break;
	}
	gcc_assert(TREE_CODE(field) == FIELD_DECL);
	return field;
}

/* Get the type of the intentional_overflow attribute of a node
 *  * MARK_TURN_OFF
 *  * MARK_YES
 *  * MARK_NO
 *  * MARK_END_INTENTIONAL
 */
enum intentional_mark get_intentional_attr_type(const_tree node)
{
	const_tree cur_decl;

	if (node == NULL_TREE)
		return MARK_NO;

	switch (TREE_CODE(node)) {
	case COMPONENT_REF:
		cur_decl = search_field_decl(node);
		if (is_turn_off_intentional_attr(cur_decl))
			return MARK_TURN_OFF;
		if (is_end_intentional_intentional_attr(cur_decl))
			return MARK_YES;
		break;
	case PARM_DECL: {
		unsigned int argnum;

		cur_decl = get_orig_fndecl(current_function_decl);
		argnum = find_arg_number_tree(node, cur_decl);
		if (argnum == CANNOT_FIND_ARG)
			return MARK_NO;
		if (is_yes_intentional_attr(cur_decl, argnum))
			return MARK_YES;
		if (is_end_intentional_intentional_attr(cur_decl))
			return MARK_END_INTENTIONAL;
		break;
	}
	case FUNCTION_DECL: {
		const_tree fndecl = get_orig_fndecl(node);

		if (is_turn_off_intentional_attr(fndecl))
			return MARK_TURN_OFF;
		if (is_end_intentional_intentional_attr(fndecl))
			return MARK_END_INTENTIONAL;
		break;
	}
	case FIELD_DECL:
	case VAR_DECL:
		if (is_end_intentional_intentional_attr(node))
			return MARK_END_INTENTIONAL;
		if (is_turn_off_intentional_attr(node))
			return MARK_TURN_OFF;
	default:
		break;
	}
	return MARK_NO;
}

static enum intentional_mark walk_use_def_phi(gimple_set *visited, const_tree result)
{
	enum intentional_mark mark = MARK_NO;
	gphi *phi = as_a_gphi(get_def_stmt(result));
	unsigned int i, n = gimple_phi_num_args(phi);

	pointer_set_insert(visited, phi);
	for (i = 0; i < n; i++) {
		tree arg = gimple_phi_arg_def(phi, i);

		mark = walk_use_def(visited, arg);
		if (mark != MARK_NO)
			return mark;
	}

	return mark;
}

static enum intentional_mark walk_use_def_binary(gimple_set *visited, const_tree lhs)
{
	enum intentional_mark mark;
	tree rhs1, rhs2;
	gassign *def_stmt = as_a_gassign(get_def_stmt(lhs));

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);

	mark = walk_use_def(visited, rhs1);
	if (mark == MARK_NO)
		return walk_use_def(visited, rhs2);
	return mark;
}

enum intentional_mark get_so_asm_type(const_gimple stmt)
{
	const gasm *asm_stmt;

	if (!stmt)
		return MARK_NO;
	if (!is_size_overflow_asm(stmt))
		return MARK_NO;

	asm_stmt = as_a_const_gasm(stmt);
	if (is_size_overflow_insert_check_asm(asm_stmt))
		return MARK_NO;
	if (is_size_overflow_intentional_asm_turn_off(asm_stmt))
		return MARK_TURN_OFF;
	if (is_size_overflow_intentional_asm_end(asm_stmt))
		return MARK_END_INTENTIONAL;
	return MARK_YES;
}

static enum intentional_mark walk_use_def(gimple_set *visited, const_tree lhs)
{
	const_gimple def_stmt;

	if (TREE_CODE(lhs) != SSA_NAME)
		return get_intentional_attr_type(lhs);

	def_stmt = get_def_stmt(lhs);
	gcc_assert(def_stmt);

	if (pointer_set_insert(visited, def_stmt))
		return MARK_NO;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_CALL:
	case GIMPLE_RETURN:
		return MARK_NO;
	case GIMPLE_NOP:
		return walk_use_def(visited, SSA_NAME_VAR(lhs));
	case GIMPLE_ASM:
		return get_so_asm_type(as_a_const_gasm(def_stmt));
	case GIMPLE_PHI:
		return walk_use_def_phi(visited, lhs);
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			return walk_use_def(visited, gimple_assign_rhs1(def_stmt));
		case 3:
			return walk_use_def_binary(visited, lhs);
		}
	default:
		debug_gimple_stmt((gimple)def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

enum intentional_mark check_intentional_size_overflow_asm_and_attribute(const_tree var)
{
	enum intentional_mark mark;
	gimple_set *visited;

	if (is_turn_off_intentional_attr(get_orig_fndecl(current_function_decl)))
		return MARK_TURN_OFF;

	visited = pointer_set_create();
	mark = walk_use_def(visited, var);
	pointer_set_destroy(visited);

	return mark;
}

/* Search intentional_overflow attribute on caller and on callee too.
 * -1 / MARK_TURN_OFF: means that overflow checking is turned off inside the function and
 *                     parameters aren't tracked backwards.
 * 1..31 / MARK_YES: e.g., 4 means that overflow checking is turned off on the fourth parameter inside
 *                   the function.
 * 0 / MARK_END_INTENTIONAL: means that overflow checking is turned off on all the parameters of the function
 *                           in all callers (on a structure field means that overflow checking is turned off
 *                           in all expressions involving the given field).
 */
enum intentional_mark check_intentional_attribute(const_gimple stmt, unsigned int argnum)
{
	enum intentional_mark caller_mark, callee_mark;
	tree fndecl;
	const_tree orig_cur_fndecl, arg;

	orig_cur_fndecl = get_orig_fndecl(current_function_decl);

	// handle MARK_TURN_OFF early on the caller
	if (is_turn_off_intentional_attr(orig_cur_fndecl))
		return MARK_TURN_OFF;
	// handle MARK_END_INTENTIONAL on the caller
	if (is_end_intentional_intentional_attr(orig_cur_fndecl))
		return MARK_END_INTENTIONAL;

	switch (gimple_code(stmt)) {
	case GIMPLE_RETURN:
		gcc_assert(argnum == 0);
		// for now ignore other intentional attribute types on returns
		return MARK_NO;
	case GIMPLE_CALL:
		gcc_assert(argnum != 0);
		gcc_assert(argnum <= gimple_call_num_args(stmt));
		arg = gimple_call_arg(stmt, argnum - 1);
		break;
	default:
		debug_gimple_stmt((gimple)stmt);
		gcc_unreachable();
	}

	// XXX ideiglenesen 0-nal a fuggvenyen belul is ki van kapcsolva a dupolas, eddig igy mukodott a doksi ellenere
	if (is_end_intentional_intentional_attr(orig_cur_fndecl))
		return MARK_END_INTENTIONAL;

	fndecl = get_interesting_orig_fndecl_from_stmt(as_a_const_gcall(stmt));
	// handle MARK_TURN_OFF on the callee
	if (is_turn_off_intentional_attr(fndecl))
		return MARK_TURN_OFF;
	// find a defining marked caller argument or struct field for arg
	caller_mark = check_intentional_size_overflow_asm_and_attribute(arg);

	// did we find a marked struct field?
	if (caller_mark == MARK_TURN_OFF)
		return MARK_TURN_OFF;

	// handle MARK_END_INTENTIONAL on the callee
	if (is_end_intentional_intentional_attr(fndecl))
		callee_mark = MARK_END_INTENTIONAL;
	// is it a marked callee parameter?
	else if (is_yes_intentional_attr(fndecl, argnum))
		callee_mark = MARK_YES;
	else
		callee_mark = MARK_NO;

	// no intentional attribute found
	if (callee_mark == MARK_NO && caller_mark == MARK_NO)
		return MARK_NO;

	// MARK_YES is meaningful only on the caller
	if (caller_mark == MARK_NO && callee_mark == MARK_YES)
		return MARK_NO;

	// we found a code region where we don't want to duplicate
	if (caller_mark == MARK_YES && callee_mark == MARK_END_INTENTIONAL)
		return MARK_END_INTENTIONAL;

	// ignore the intentional attribute on the callee if we didn't find a marked defining argument or struct field
	if (caller_mark == MARK_NO && callee_mark == MARK_END_INTENTIONAL)
		return MARK_NO;

	// the callee is missing the intentional attribute (MARK_YES or MARK_END_INTENTIONAL)
	if (caller_mark == MARK_YES) {
		print_missing_intentional(callee_mark, caller_mark, fndecl, argnum);
		return MARK_YES;
	}

	fprintf(stderr, "caller: %s callee: %s\n", DECL_NAME_POINTER(orig_cur_fndecl), DECL_NAME_POINTER(fndecl));
	debug_gimple_stmt((gimple)stmt);
	print_intentional_mark(caller_mark);
	print_intentional_mark(callee_mark);
	gcc_unreachable();
}

bool is_a_cast_and_const_overflow(const_tree no_const_rhs)
{
	const_tree rhs1, lhs, rhs1_type, lhs_type;
	enum machine_mode lhs_mode, rhs_mode;
	gimple def_stmt = get_def_stmt(no_const_rhs);

	if (!def_stmt || !gimple_assign_cast_p(def_stmt))
		return false;

	rhs1 = gimple_assign_rhs1(def_stmt);
	lhs = gimple_assign_lhs(def_stmt);
	rhs1_type = TREE_TYPE(rhs1);
	lhs_type = TREE_TYPE(lhs);
	rhs_mode = TYPE_MODE(rhs1_type);
	lhs_mode = TYPE_MODE(lhs_type);
	if (TYPE_UNSIGNED(lhs_type) == TYPE_UNSIGNED(rhs1_type) || lhs_mode != rhs_mode)
		return false;

	return true;
}

static unsigned int uses_num(tree node)
{
	imm_use_iterator imm_iter;
	use_operand_p use_p;
	unsigned int num = 0;

	FOR_EACH_IMM_USE_FAST(use_p, imm_iter, node) {
		gimple use_stmt = USE_STMT(use_p);

		if (use_stmt == NULL)
			return num;
		if (is_gimple_debug(use_stmt))
			continue;
		if (gimple_assign_cast_p(use_stmt) && is_size_overflow_type(gimple_assign_lhs(use_stmt)))
			continue;
		num++;
	}
	return num;
}

static bool no_uses(tree node)
{
	return !uses_num(node);
}

// 3.8.5 mm/page-writeback.c __ilog2_u64(): ret, uint + uintmax; uint -> int; int max
bool is_const_plus_unsigned_signed_truncation(const_tree lhs)
{
	tree rhs1, lhs_type, rhs_type, rhs2, not_const_rhs;
	gimple def_stmt = get_def_stmt(lhs);

	if (!def_stmt || !gimple_assign_cast_p(def_stmt))
		return false;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs_type = TREE_TYPE(rhs1);
	lhs_type = TREE_TYPE(lhs);
	if (TYPE_UNSIGNED(lhs_type) || !TYPE_UNSIGNED(rhs_type))
		return false;
	if (TYPE_MODE(lhs_type) != TYPE_MODE(rhs_type))
		return false;

	def_stmt = get_def_stmt(rhs1);
	if (!def_stmt || !is_gimple_assign(def_stmt) || gimple_num_ops(def_stmt) != 3)
		return false;

	if (gimple_assign_rhs_code(def_stmt) != PLUS_EXPR)
		return false;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	if (!is_gimple_constant(rhs1) && !is_gimple_constant(rhs2))
		return false;

	if (is_gimple_constant(rhs2))
		not_const_rhs = rhs1;
	else
		not_const_rhs = rhs2;

	return no_uses(not_const_rhs);
}

static bool is_lt_signed_type_max(const_tree rhs)
{
	const_tree new_type, type_max, type = TREE_TYPE(rhs);

	if (!TYPE_UNSIGNED(type))
		return true;

	switch (TYPE_MODE(type)) {
	case QImode:
		new_type = intQI_type_node;
		break;
	case HImode:
		new_type = intHI_type_node;
		break;
	case SImode:
		new_type = intSI_type_node;
		break;
	case DImode:
		new_type = intDI_type_node;
		break;
	default:
		debug_tree(type);
		gcc_unreachable();
	}

	type_max = TYPE_MAX_VALUE(new_type);
	if (!tree_int_cst_lt(type_max, rhs))
		return true;

	return false;
}

static bool is_gt_zero(const_tree rhs)
{
	const_tree type = TREE_TYPE(rhs);

	if (TYPE_UNSIGNED(type))
		return true;

	if (!tree_int_cst_lt(rhs, integer_zero_node))
		return true;

	return false;
}

bool is_a_constant_overflow(const gassign *stmt, const_tree rhs)
{
	if (gimple_assign_rhs_code(stmt) == MIN_EXPR)
		return false;
	if (!is_gimple_constant(rhs))
		return false;

	// if the const is between 0 and the max value of the signed type of the same bitsize then there is no intentional overflow
	if (is_lt_signed_type_max(rhs) && is_gt_zero(rhs))
		return false;

	return true;
}

static tree change_assign_rhs(struct visited *visited, gassign *stmt, const_tree orig_rhs, tree new_rhs)
{
	const_gimple assign;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);
	tree origtype = TREE_TYPE(orig_rhs);

	assign = build_cast_stmt(visited, origtype, new_rhs, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	pointer_set_insert(visited->my_stmts, assign);
	return get_lhs(assign);
}

tree handle_intentional_overflow(interesting_stmts_t expand_from, bool check_overflow, gassign *stmt, tree change_rhs, tree new_rhs2)
{
	tree new_rhs, orig_rhs;
	void (*gimple_assign_set_rhs)(gimple, tree);
	tree rhs1 = gimple_assign_rhs1(stmt);
	tree rhs2 = gimple_assign_rhs2(stmt);
	tree lhs = gimple_assign_lhs(stmt);

	if (!check_overflow)
		return create_assign(expand_from->visited, stmt, lhs, AFTER_STMT);

	if (change_rhs == NULL_TREE)
		return create_assign(expand_from->visited, stmt, lhs, AFTER_STMT);

	if (new_rhs2 == NULL_TREE) {
		orig_rhs = rhs1;
		gimple_assign_set_rhs = &gimple_assign_set_rhs1;
	} else {
		orig_rhs = rhs2;
		gimple_assign_set_rhs = &gimple_assign_set_rhs2;
	}

	check_size_overflow(expand_from, stmt, TREE_TYPE(change_rhs), change_rhs, orig_rhs, BEFORE_STMT);

	new_rhs = change_assign_rhs(expand_from->visited, stmt, orig_rhs, change_rhs);
	gimple_assign_set_rhs(stmt, new_rhs);
	update_stmt(stmt);

	return create_assign(expand_from->visited, stmt, lhs, AFTER_STMT);
}

static bool is_subtraction_special(struct visited *visited, const gassign *stmt)
{
	gimple rhs1_def_stmt, rhs2_def_stmt;
	const_tree rhs1_def_stmt_rhs1, rhs2_def_stmt_rhs1, rhs1_def_stmt_lhs, rhs2_def_stmt_lhs;
	enum machine_mode rhs1_def_stmt_rhs1_mode, rhs2_def_stmt_rhs1_mode, rhs1_def_stmt_lhs_mode, rhs2_def_stmt_lhs_mode;
	const_tree rhs1 = gimple_assign_rhs1(stmt);
	const_tree rhs2 = gimple_assign_rhs2(stmt);

	if (is_gimple_constant(rhs1) || is_gimple_constant(rhs2))
		return false;

	if (gimple_assign_rhs_code(stmt) != MINUS_EXPR)
		return false;

	gcc_assert(TREE_CODE(rhs1) == SSA_NAME && TREE_CODE(rhs2) == SSA_NAME);

	rhs1_def_stmt = get_def_stmt(rhs1);
	rhs2_def_stmt = get_def_stmt(rhs2);
	if (!gimple_assign_cast_p(rhs1_def_stmt) || !gimple_assign_cast_p(rhs2_def_stmt))
		return false;

	rhs1_def_stmt_rhs1 = gimple_assign_rhs1(rhs1_def_stmt);
	rhs2_def_stmt_rhs1 = gimple_assign_rhs1(rhs2_def_stmt);
	rhs1_def_stmt_lhs = gimple_assign_lhs(rhs1_def_stmt);
	rhs2_def_stmt_lhs = gimple_assign_lhs(rhs2_def_stmt);
	rhs1_def_stmt_rhs1_mode = TYPE_MODE(TREE_TYPE(rhs1_def_stmt_rhs1));
	rhs2_def_stmt_rhs1_mode = TYPE_MODE(TREE_TYPE(rhs2_def_stmt_rhs1));
	rhs1_def_stmt_lhs_mode = TYPE_MODE(TREE_TYPE(rhs1_def_stmt_lhs));
	rhs2_def_stmt_lhs_mode = TYPE_MODE(TREE_TYPE(rhs2_def_stmt_lhs));
	if (GET_MODE_BITSIZE(rhs1_def_stmt_rhs1_mode) <= GET_MODE_BITSIZE(rhs1_def_stmt_lhs_mode))
		return false;
	if (GET_MODE_BITSIZE(rhs2_def_stmt_rhs1_mode) <= GET_MODE_BITSIZE(rhs2_def_stmt_lhs_mode))
		return false;

	pointer_set_insert(visited->no_cast_check, rhs1_def_stmt);
	pointer_set_insert(visited->no_cast_check, rhs2_def_stmt);
	return true;
}

static gassign *create_binary_assign(struct visited *visited, enum tree_code code, gassign *stmt, tree rhs1, tree rhs2)
{
	gassign *assign;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);
	tree type = TREE_TYPE(rhs1);
	tree lhs = create_new_var(type);

	gcc_assert(types_compatible_p(type, TREE_TYPE(rhs2)));
	assign = as_a_gassign(gimple_build_assign_with_ops(code, lhs, rhs1, rhs2));
	gimple_assign_set_lhs(assign, make_ssa_name(lhs, assign));

	gsi_insert_before(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
	pointer_set_insert(visited->my_stmts, assign);
	return assign;
}

static tree cast_to_TI_type(struct visited *visited, gassign *stmt, tree node)
{
	gimple_stmt_iterator gsi;
	const_gimple cast_stmt;
	tree type = TREE_TYPE(node);

	if (types_compatible_p(type, intTI_type_node))
		return node;

	gsi = gsi_for_stmt(stmt);
	cast_stmt = build_cast_stmt(visited, intTI_type_node, node, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	pointer_set_insert(visited->my_stmts, cast_stmt);
	return get_lhs(cast_stmt);
}

static tree get_def_stmt_rhs(struct visited *visited, const_tree var)
{
	tree rhs1, def_stmt_rhs1;
	gimple rhs1_def_stmt, def_stmt_rhs1_def_stmt, def_stmt;

	def_stmt = get_def_stmt(var);
	if (!gimple_assign_cast_p(def_stmt))
		return NULL_TREE;
	gcc_assert(gimple_code(def_stmt) != GIMPLE_NOP && pointer_set_contains(visited->my_stmts, def_stmt) && gimple_assign_cast_p(def_stmt));

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs1_def_stmt = get_def_stmt(rhs1);
	if (!gimple_assign_cast_p(rhs1_def_stmt))
		return rhs1;

	def_stmt_rhs1 = gimple_assign_rhs1(rhs1_def_stmt);
	def_stmt_rhs1_def_stmt = get_def_stmt(def_stmt_rhs1);

	switch (gimple_code(def_stmt_rhs1_def_stmt)) {
	case GIMPLE_CALL:
	case GIMPLE_NOP:
	case GIMPLE_ASM:
	case GIMPLE_PHI:
		return def_stmt_rhs1;
	case GIMPLE_ASSIGN:
		return rhs1;
	default:
		debug_gimple_stmt(def_stmt_rhs1_def_stmt);
		gcc_unreachable();
	}
}

tree handle_integer_truncation(interesting_stmts_t expand_from, const_tree lhs)
{
	tree new_rhs1, new_rhs2;
	tree new_rhs1_def_stmt_rhs1, new_rhs2_def_stmt_rhs1, new_lhs;
	gassign *assign, *stmt = as_a_gassign(get_def_stmt(lhs));
	tree rhs1 = gimple_assign_rhs1(stmt);
	tree rhs2 = gimple_assign_rhs2(stmt);

	if (!is_subtraction_special(expand_from->visited, stmt))
		return NULL_TREE;

	new_rhs1 = expand(expand_from, rhs1);
	new_rhs2 = expand(expand_from, rhs2);

	new_rhs1_def_stmt_rhs1 = get_def_stmt_rhs(expand_from->visited, new_rhs1);
	new_rhs2_def_stmt_rhs1 = get_def_stmt_rhs(expand_from->visited, new_rhs2);

	if (new_rhs1_def_stmt_rhs1 == NULL_TREE || new_rhs2_def_stmt_rhs1 == NULL_TREE)
		return NULL_TREE;

	if (!types_compatible_p(TREE_TYPE(new_rhs1_def_stmt_rhs1), TREE_TYPE(new_rhs2_def_stmt_rhs1))) {
		new_rhs1_def_stmt_rhs1 = cast_to_TI_type(expand_from->visited, stmt, new_rhs1_def_stmt_rhs1);
		new_rhs2_def_stmt_rhs1 = cast_to_TI_type(expand_from->visited, stmt, new_rhs2_def_stmt_rhs1);
	}

	assign = create_binary_assign(expand_from->visited, MINUS_EXPR, stmt, new_rhs1_def_stmt_rhs1, new_rhs2_def_stmt_rhs1);
	new_lhs = gimple_assign_lhs(assign);
	check_size_overflow(expand_from, assign, TREE_TYPE(new_lhs), new_lhs, rhs1, AFTER_STMT);

	return dup_assign(expand_from->visited, stmt, lhs, new_rhs1, new_rhs2, NULL_TREE);
}

bool is_a_neg_overflow(const gassign *stmt, const_tree rhs)
{
	const_gimple def_stmt;

	if (TREE_CODE(rhs) != SSA_NAME)
		return false;

	if (gimple_assign_rhs_code(stmt) != PLUS_EXPR)
		return false;

	def_stmt = get_def_stmt(rhs);
	if (!is_gimple_assign(def_stmt) || gimple_assign_rhs_code(def_stmt) != BIT_NOT_EXPR)
		return false;

	return true;
}

/* e.g., drivers/acpi/acpica/utids.c acpi_ut_execute_CID()
 * ((count - 1) * sizeof(struct acpi_pnp_dee_id_list) -> (count + fffffff) * 16
 * fffffff * 16 > signed max -> truncate
 */
static bool look_for_mult_and_add(const_gimple stmt)
{
	const_tree res;
	tree rhs1, rhs2, def_rhs1, def_rhs2, const_rhs, def_const_rhs;
	const_gimple def_stmt;

	if (!stmt || gimple_code(stmt) == GIMPLE_NOP)
		return false;
	if (!is_gimple_assign(stmt))
		return false;
	if (gimple_assign_rhs_code(stmt) != MULT_EXPR)
		return false;

	rhs1 = gimple_assign_rhs1(stmt);
	rhs2 = gimple_assign_rhs2(stmt);
	if (is_gimple_constant(rhs1)) {
		const_rhs = rhs1;
		def_stmt = get_def_stmt(rhs2);
	} else if (is_gimple_constant(rhs2)) {
		const_rhs = rhs2;
		def_stmt = get_def_stmt(rhs1);
	} else
		return false;

	if (!is_gimple_assign(def_stmt))
		return false;

	if (gimple_assign_rhs_code(def_stmt) != PLUS_EXPR && gimple_assign_rhs_code(def_stmt) != MINUS_EXPR)
		return false;

	def_rhs1 = gimple_assign_rhs1(def_stmt);
	def_rhs2 = gimple_assign_rhs2(def_stmt);
	if (is_gimple_constant(def_rhs1))
		def_const_rhs = def_rhs1;
	else if (is_gimple_constant(def_rhs2))
		def_const_rhs = def_rhs2;
	else
		return false;

	res = fold_binary_loc(gimple_location(def_stmt), MULT_EXPR, TREE_TYPE(const_rhs), const_rhs, def_const_rhs);
	if (is_lt_signed_type_max(res) && is_gt_zero(res))
		return false;
	return true;
}

enum intentional_overflow_type add_mul_intentional_overflow(const gassign *stmt)
{
	const_gimple def_stmt_1, def_stmt_2;
	const_tree rhs1, rhs2;
	bool add_mul_rhs1, add_mul_rhs2;

	rhs1 = gimple_assign_rhs1(stmt);
	def_stmt_1 = get_def_stmt(rhs1);
	add_mul_rhs1 = look_for_mult_and_add(def_stmt_1);

	rhs2 = gimple_assign_rhs2(stmt);
	def_stmt_2 = get_def_stmt(rhs2);
	add_mul_rhs2 = look_for_mult_and_add(def_stmt_2);

	if (add_mul_rhs1)
		return RHS1_INTENTIONAL_OVERFLOW;
	if (add_mul_rhs2)
		return RHS2_INTENTIONAL_OVERFLOW;
	return NO_INTENTIONAL_OVERFLOW;
}

static gassign *get_dup_stmt(struct visited *visited, gassign *stmt)
{
	gassign *my_stmt;
	gimple_stmt_iterator gsi = gsi_for_stmt(stmt);

	gsi_next(&gsi);
	my_stmt = as_a_gassign(gsi_stmt(gsi));

	gcc_assert(pointer_set_contains(visited->my_stmts, my_stmt));
	if (gimple_assign_cast_p(stmt) && gimple_assign_cast_p(my_stmt))
		return my_stmt;

	if (gimple_assign_rhs_code(stmt) != gimple_assign_rhs_code(my_stmt)) {
		fprintf(stderr, "%s != %s\n", get_tree_code_name(gimple_assign_rhs_code(stmt)), get_tree_code_name(gimple_assign_rhs_code(my_stmt)));
		debug_gimple_stmt(stmt);
		debug_gimple_stmt(my_stmt);
		gcc_unreachable();
	}

	return my_stmt;
}

/* unsigned type -> unary or binary assign (rhs1 or rhs2 is constant)
 * unsigned type cast to signed type, unsigned type: no more uses
 * e.g., lib/vsprintf.c:simple_strtol()
 * _10 = (unsigned long int) _9
 * _11 = -_10;
 * _12 = (long int) _11; (_11_ no more uses)
 */
static bool is_call_or_cast(gimple stmt)
{
	return gimple_assign_cast_p(stmt) || is_gimple_call(stmt);
}

static bool is_unsigned_cast_or_call_def_stmt(const_tree node)
{
	const_tree rhs;
	gimple def_stmt;

	if (node == NULL_TREE)
		return true;
	if (is_gimple_constant(node))
		return true;

	def_stmt = get_def_stmt(node);
	if (!def_stmt)
		return false;

	if (is_call_or_cast(def_stmt))
		return true;

	if (!is_gimple_assign(def_stmt) || gimple_num_ops(def_stmt) != 2)
		return false;
	rhs = gimple_assign_rhs1(def_stmt);
	def_stmt = get_def_stmt(rhs);
	if (!def_stmt)
		return false;
	return is_call_or_cast(def_stmt);
}

void unsigned_signed_cast_intentional_overflow(struct visited *visited, gassign *stmt)
{
	unsigned int use_num;
	gassign *so_stmt;
	const_gimple def_stmt;
	const_tree rhs1, rhs2;
	tree rhs = gimple_assign_rhs1(stmt);
	tree lhs_type = TREE_TYPE(gimple_assign_lhs(stmt));
	const_tree rhs_type = TREE_TYPE(rhs);

	if (!(TYPE_UNSIGNED(rhs_type) && !TYPE_UNSIGNED(lhs_type)))
		return;
	if (GET_MODE_BITSIZE(TYPE_MODE(rhs_type)) != GET_MODE_BITSIZE(TYPE_MODE(lhs_type)))
		return;
	use_num = uses_num(rhs);
	if (use_num != 1)
		return;

	def_stmt = get_def_stmt(rhs);
	if (!def_stmt)
		return;
	if (!is_gimple_assign(def_stmt))
		return;

	rhs1 = gimple_assign_rhs1(def_stmt);
	if (!is_unsigned_cast_or_call_def_stmt(rhs1))
		return;

	rhs2 = gimple_assign_rhs2(def_stmt);
	if (!is_unsigned_cast_or_call_def_stmt(rhs2))
		return;
	if (gimple_num_ops(def_stmt) == 3 && !is_gimple_constant(rhs1) && !is_gimple_constant(rhs2))
		return;

	so_stmt = get_dup_stmt(visited, stmt);
	create_up_and_down_cast(visited, so_stmt, lhs_type, gimple_assign_rhs1(so_stmt));
}

/* gcc intentional overflow
 * e.g., skb_set_network_header(), skb_set_mac_header()
 * -, int offset + u16 network_header
 * offset = -x->props.header_len
 * skb->network_header += offset;
 *
 * SSA
 * _141 = -_140;
 * _154 = (short unsigned int) _141;
 * _155 = (size_overflow_type_SI) _154;
 * _156 = _154 + _155; // 2x
 * _157 = (short unsigned int) _156;
 */
static bool is_short_cast_neg(const_tree rhs)
{
	const_tree cast_rhs;
	const_gimple neg_stmt;
	gimple neg_cast_stmt, cast_stmt = get_def_stmt(rhs);

	if (!cast_stmt || !gimple_assign_cast_p(cast_stmt))
		return false;

	cast_rhs = gimple_assign_rhs1(cast_stmt);
	if (GET_MODE_BITSIZE(TYPE_MODE(TREE_TYPE(cast_rhs))) >= GET_MODE_BITSIZE(TYPE_MODE(TREE_TYPE(rhs))))
		return false;

	neg_cast_stmt = get_def_stmt(cast_rhs);
	if (!neg_cast_stmt || !gimple_assign_cast_p(neg_cast_stmt))
		return false;

	neg_stmt = get_def_stmt(gimple_assign_rhs1(neg_cast_stmt));
	if (!neg_stmt || !is_gimple_assign(neg_stmt))
		return false;
	return gimple_assign_rhs_code(neg_stmt) == NEGATE_EXPR;
}

static bool check_add_stmt(const_tree node)
{
	const_gimple add_stmt;
	const_tree add_rhs1, add_rhs2;

	if (node == NULL_TREE)
		return false;

	add_stmt = get_def_stmt(node);
	if (!add_stmt || !is_gimple_assign(add_stmt) || gimple_assign_rhs_code(add_stmt) != PLUS_EXPR)
		return false;

	add_rhs1 = gimple_assign_rhs1(add_stmt);
	add_rhs2 = gimple_assign_rhs2(add_stmt);
	return is_short_cast_neg(add_rhs1) || is_short_cast_neg(add_rhs2);
}

bool neg_short_add_intentional_overflow(gassign *unary_stmt)
{
	const_tree rhs1, add_rhs1, add_rhs2, cast_rhs;
	gimple cast_stmt;
	const_gimple add_stmt;

	rhs1 = gimple_assign_rhs1(unary_stmt);

	cast_stmt = get_def_stmt(rhs1);
	if (!cast_stmt || !gimple_assign_cast_p(cast_stmt))
		return false;
	cast_rhs = gimple_assign_rhs1(cast_stmt);
	if (GET_MODE_BITSIZE(TYPE_MODE(TREE_TYPE(cast_rhs))) <= GET_MODE_BITSIZE(TYPE_MODE(TREE_TYPE(rhs1))))
		return false;

	// one or two plus expressions
	if (check_add_stmt(cast_rhs))
		return true;

	add_stmt = get_def_stmt(cast_rhs);
	if (!add_stmt || !is_gimple_assign(add_stmt))
		return false;
	add_rhs1 = gimple_assign_rhs1(add_stmt);
	if (check_add_stmt(add_rhs1))
		return true;
	add_rhs2 = gimple_assign_rhs2(add_stmt);
	return check_add_stmt(add_rhs2);
}

/* True:
 * _25 = (<unnamed-unsigned:1>) _24;
 * r_5(D)->stereo = _25;
 */
bool is_bitfield_unnamed_cast(const_tree decl, gassign *assign)
{
	const_tree rhs, type;
	gimple def_stmt;

	if (TREE_CODE(decl) != FIELD_DECL)
		return false;
	if (!DECL_BIT_FIELD_TYPE(decl))
		return false;
	if (gimple_num_ops(assign) != 2)
		return false;

	rhs = gimple_assign_rhs1(assign);
	if (is_gimple_constant(rhs))
		return false;
	type = TREE_TYPE(rhs);
	if (TREE_CODE(type) == BOOLEAN_TYPE)
		return false;

	def_stmt = get_def_stmt(rhs);
	if (!gimple_assign_cast_p(def_stmt))
		return false;
	return TYPE_PRECISION(type) < CHAR_TYPE_SIZE;
}

static bool is_mult_const(const_tree lhs)
{
	const_gimple def_stmt;
	const_tree rhs1, rhs2;

	def_stmt = get_def_stmt(lhs);
	if (!def_stmt || !is_gimple_assign(def_stmt) || gimple_assign_rhs_code(def_stmt) != MULT_EXPR)
		return false;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	if (is_gimple_constant(rhs1))
		return !is_lt_signed_type_max(rhs1);
	else if (is_gimple_constant(rhs2))
		return !is_lt_signed_type_max(rhs2);
	return false;
}

/* True:
 * fs/cifs/file.c cifs_write_from_iter()
 * u32 = u64 - (u64 - constant) * constant
 * wdata->tailsz = cur_len - (nr_pages - 1) * PAGE_SIZE;
 *
 * _51 = _50 * 4294963200;
 * _52 = _49 + _51;
 * _53 = _52 + 4096;
 */

bool uconst_neg_intentional_overflow(const gassign *stmt)
{
	const_gimple def_stmt;
	const_tree noconst_rhs;
	tree rhs1, rhs2;

	// _53 = _52 + const;
	if (gimple_assign_rhs_code(stmt) != PLUS_EXPR)
		return false;
	rhs1 = gimple_assign_rhs1(stmt);
	rhs2 = gimple_assign_rhs2(stmt);
	if (is_gimple_constant(rhs1))
		noconst_rhs = rhs2;
	else if (is_gimple_constant(rhs2))
		noconst_rhs = rhs1;
	else
		return false;
	def_stmt = get_def_stmt(noconst_rhs);

	// _52 = _49 + _51;
	if (!def_stmt)
		return false;
	if (!is_gimple_assign(def_stmt))
		return false;
	if (gimple_assign_rhs_code(def_stmt) != PLUS_EXPR)
		return false;
	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);
	if (is_gimple_constant(rhs1) || is_gimple_constant(rhs2))
		return false;

	// _51 = _50 * gt signed type max;
	return is_mult_const(rhs1) || is_mult_const(rhs2);
}

/* True:
 * drivers/net/ethernet/via/via-velocity.c velocity_rx_refill()
 * u16 = cpu_to_le16(s32) | const
 * rd->size = cpu_to_le16(vptr->rx.buf_sz) | RX_INTEN;
 *
 * _36 = (signed short) _35;
 * _37 = _36 | -32768;
 * _38 = (short unsigned int) _37;
 */

bool short_or_neg_const_ushort(gassign *stmt)
{
	const_tree rhs, lhs_type, rhs_type;
	const_tree def_rhs1, def_rhs2;
	const_gimple def_stmt;
	gimple def_def_stmt = NULL;

	if (!gimple_assign_cast_p(stmt))
		return false;

	// _38 = (short unsigned int) _37;
	lhs_type = TREE_TYPE(gimple_assign_lhs(stmt));
	if (!TYPE_UNSIGNED(lhs_type))
		return false;
	if (TYPE_MODE(lhs_type) != HImode)
		return false;
	rhs = gimple_assign_rhs1(stmt);
	rhs_type = TREE_TYPE(rhs);
	if (TYPE_UNSIGNED(rhs_type))
		return false;
	if (TYPE_MODE(rhs_type) != HImode)
		return false;

	// _37 = _36 | -32768;
	def_stmt = get_def_stmt(rhs);
	if (!def_stmt || !is_gimple_assign(def_stmt) || gimple_assign_rhs_code(def_stmt) != BIT_IOR_EXPR)
		return false;
	def_rhs1 = gimple_assign_rhs1(def_stmt);
	def_rhs2 = gimple_assign_rhs2(def_stmt);
	if (is_gimple_constant(def_rhs1) && !is_gt_zero(def_rhs1))
		def_def_stmt = get_def_stmt(def_rhs2);
	else if (is_gimple_constant(def_rhs2) && !is_gt_zero(def_rhs2))
		def_def_stmt = get_def_stmt(def_rhs1);

	// _36 = (signed short) _35;
	return def_def_stmt && gimple_assign_cast_p(def_def_stmt);
}
