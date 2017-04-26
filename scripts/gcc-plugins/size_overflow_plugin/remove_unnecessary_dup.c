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

bool skip_expr_on_double_type(const gassign *stmt)
{
	enum tree_code code = gimple_assign_rhs_code(stmt);

	switch (code) {
	case RSHIFT_EXPR:
	case TRUNC_DIV_EXPR:
	case CEIL_DIV_EXPR:
	case FLOOR_DIV_EXPR:
	case ROUND_DIV_EXPR:
	case EXACT_DIV_EXPR:
	case RDIV_EXPR:
	case TRUNC_MOD_EXPR:
	case CEIL_MOD_EXPR:
	case FLOOR_MOD_EXPR:
	case ROUND_MOD_EXPR:
		return true;
	default:
		return false;
	}
}

void create_up_and_down_cast(struct visited *visited, gassign *use_stmt, tree orig_type, tree rhs)
{
	const_tree orig_rhs1;
	tree down_lhs, new_lhs, dup_type = TREE_TYPE(rhs);
	const_gimple down_cast, up_cast;
	gimple_stmt_iterator gsi = gsi_for_stmt(use_stmt);

	down_cast = build_cast_stmt(visited, orig_type, rhs, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	down_lhs = get_lhs(down_cast);

	gsi = gsi_for_stmt(use_stmt);
	up_cast = build_cast_stmt(visited, dup_type, down_lhs, CREATE_NEW_VAR, &gsi, BEFORE_STMT, false);
	new_lhs = get_lhs(up_cast);

	orig_rhs1 = gimple_assign_rhs1(use_stmt);
	if (operand_equal_p(orig_rhs1, rhs, 0))
		gimple_assign_set_rhs1(use_stmt, new_lhs);
	else
		gimple_assign_set_rhs2(use_stmt, new_lhs);
	update_stmt(use_stmt);

	pointer_set_insert(visited->my_stmts, up_cast);
	pointer_set_insert(visited->my_stmts, down_cast);
	pointer_set_insert(visited->skip_expr_casts, up_cast);
	pointer_set_insert(visited->skip_expr_casts, down_cast);
}

static tree get_proper_unsigned_half_type(const_tree node)
{
	tree new_type, type;

	gcc_assert(is_size_overflow_type(node));

	type = TREE_TYPE(node);
	switch (TYPE_MODE(type)) {
	case HImode:
		new_type = unsigned_intQI_type_node;
		break;
	case SImode:
		new_type = unsigned_intHI_type_node;
		break;
	case DImode:
		new_type = unsigned_intSI_type_node;
		break;
	case TImode:
		new_type = unsigned_intDI_type_node;
		break;
	default:
		gcc_unreachable();
	}

	if (TYPE_QUALS(type) != 0)
		return build_qualified_type(new_type, TYPE_QUALS(type));
	return new_type;
}

static void insert_cast_rhs(struct visited *visited, gassign *stmt, tree rhs)
{
	tree type;

	if (rhs == NULL_TREE)
		return;
	if (!is_size_overflow_type(rhs))
		return;

	type = get_proper_unsigned_half_type(rhs);
	if (is_gimple_constant(rhs))
		return;
	create_up_and_down_cast(visited, stmt, type, rhs);
}

static void insert_cast(struct visited *visited, gassign *stmt, tree rhs)
{
	if (LONG_TYPE_SIZE == GET_MODE_BITSIZE(SImode) && !is_size_overflow_type(rhs))
		return;
	gcc_assert(is_size_overflow_type(rhs));
	insert_cast_rhs(visited, stmt, rhs);
}

void insert_cast_expr(struct visited *visited, gassign *stmt, enum intentional_overflow_type type)
{
	tree rhs1, rhs2;

	if (type == NO_INTENTIONAL_OVERFLOW || type == RHS1_INTENTIONAL_OVERFLOW) {
		rhs1 = gimple_assign_rhs1(stmt);
		insert_cast(visited, stmt, rhs1);
	}

	if (type == NO_INTENTIONAL_OVERFLOW || type == RHS2_INTENTIONAL_OVERFLOW) {
		rhs2 = gimple_assign_rhs2(stmt);
		insert_cast(visited, stmt, rhs2);
	}
}

