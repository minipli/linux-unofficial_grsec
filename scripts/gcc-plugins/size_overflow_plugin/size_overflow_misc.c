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

bool is_vararg(const_tree fn, unsigned int num)
{
	tree arg_list;

	if (num == 0)
		return false;
	if (fn == NULL_TREE)
		return false;
	if (TREE_CODE(fn) != FUNCTION_DECL)
		return false;

	arg_list = TYPE_ARG_TYPES(TREE_TYPE(fn));
	if (arg_list == NULL_TREE)
		return false;

	if (tree_last(arg_list) == void_list_node)
		return false;

	return num >= (unsigned int)list_length(arg_list);
}

// Extract the field decl from memory references
tree get_ref_field(const_tree ref)
{
	tree field;

	// TODO: handle nested memory references
	switch (TREE_CODE(ref)) {
	case ARRAY_REF:
		return NULL_TREE;
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case INDIRECT_REF:
		field = TREE_OPERAND(ref, 0);
		break;
	case COMPONENT_REF:
		field = TREE_OPERAND(ref, 1);
		break;
	default:
		return NULL_TREE;
	}

	// TODO
	if (TREE_CODE(field) == SSA_NAME)
		return NULL_TREE;
	// TODO
	if (TREE_CODE(field) != FIELD_DECL)
		return NULL_TREE;
	// TODO
	if (TREE_CODE(field) == ADDR_EXPR)
		return NULL_TREE;

	return field;
}

const char *get_type_name_from_field(const_tree field_decl)
{
	const_tree context, type_name;

	if (TREE_CODE(field_decl) != FIELD_DECL)
		return NULL;

	context = DECL_CONTEXT(field_decl);
	// TODO
	if (TREE_CODE(context) != RECORD_TYPE)
		return NULL;
	gcc_assert(TREE_CODE(context) == RECORD_TYPE);
	type_name = TYPE_NAME(TYPE_MAIN_VARIANT(context));
	if (type_name == NULL_TREE)
		return NULL;

	if (TREE_CODE(type_name) == IDENTIFIER_NODE)
		return IDENTIFIER_POINTER(type_name);
	else if (TREE_CODE(type_name) == TYPE_DECL)
		return DECL_NAME_POINTER(type_name);

	debug_tree(field_decl);
	debug_tree(type_name);
	gcc_unreachable();
}

// Was the function created by the compiler itself?
bool made_by_compiler(const_tree decl)
{
	enum tree_code decl_code;
	struct cgraph_node *node;

	if (FUNCTION_PTR_P(decl))
		return false;
	decl_code = TREE_CODE(decl);
	if (decl_code == VAR_DECL || decl_code == FIELD_DECL)
		return false;

	gcc_assert(decl_code == FUNCTION_DECL);
	if (DECL_ABSTRACT_ORIGIN(decl) != NULL_TREE && DECL_ABSTRACT_ORIGIN(decl) != decl)
		return true;
	if (DECL_ARTIFICIAL(decl))
		return true;

	node = get_cnode(decl);
	if (!node)
		return false;
	return node->clone_of != NULL;
}

bool skip_types(const_tree var)
{
	const_tree type;

	type = TREE_TYPE(var);
	if (type == NULL_TREE)
		return true;

	switch (TREE_CODE(type)) {
		case INTEGER_TYPE:
		case ENUMERAL_TYPE:
			return false;
		default:
			return true;
	}
}

gimple get_fnptr_def_stmt(const_tree fn_ptr)
{
	gimple def_stmt;

	gcc_assert(fn_ptr != NULL_TREE);
	gcc_assert(FUNCTION_PTR_P(fn_ptr));

	if (is_gimple_constant(fn_ptr))
		return NULL;

	def_stmt = get_def_stmt(fn_ptr);
	gcc_assert(def_stmt);
	return def_stmt;
}

gimple get_def_stmt(const_tree node)
{
	gcc_assert(node != NULL_TREE);

	if (TREE_CODE(node) != SSA_NAME)
		return NULL;
	return SSA_NAME_DEF_STMT(node);
}

tree create_new_var(tree type)
{
	tree new_var = create_tmp_var(type, "cicus");

	add_referenced_var(new_var);
	return new_var;
}

static bool skip_cast(tree dst_type, const_tree rhs, bool force)
{
	const_gimple def_stmt = get_def_stmt(rhs);

	if (force)
		return false;

	if (is_gimple_constant(rhs))
		return false;

	if (!def_stmt || gimple_code(def_stmt) == GIMPLE_NOP)
		return false;

	if (!types_compatible_p(dst_type, TREE_TYPE(rhs)))
		return false;

	// DI type can be on 32 bit (from create_assign) but overflow type stays DI
	if (LONG_TYPE_SIZE == GET_MODE_BITSIZE(SImode))
		return false;

	return true;
}

tree cast_a_tree(tree type, tree var)
{
	gcc_assert(type != NULL_TREE);
	gcc_assert(var != NULL_TREE);
	gcc_assert(fold_convertible_p(type, var));

	return fold_convert(type, var);
}

gimple build_cast_stmt(struct visited *visited, tree dst_type, tree rhs, tree lhs, gimple_stmt_iterator *gsi, bool before, bool force)
{
	gassign *assign;
	gimple def_stmt;

	gcc_assert(dst_type != NULL_TREE && rhs != NULL_TREE);
	gcc_assert(!is_gimple_constant(rhs));
	if (gsi_end_p(*gsi) && before == AFTER_STMT)
		gcc_unreachable();

	def_stmt = get_def_stmt(rhs);
	if (def_stmt && gimple_code(def_stmt) != GIMPLE_NOP && skip_cast(dst_type, rhs, force) && pointer_set_contains(visited->my_stmts, def_stmt))
		return def_stmt;

	if (lhs == CREATE_NEW_VAR)
		lhs = create_new_var(dst_type);

	assign = gimple_build_assign(lhs, cast_a_tree(dst_type, rhs));

	if (!gsi_end_p(*gsi)) {
		location_t loc = gimple_location(gsi_stmt(*gsi));
		gimple_set_location(assign, loc);
	}

	gimple_assign_set_lhs(assign, make_ssa_name(lhs, assign));

	if (before)
		gsi_insert_before(gsi, assign, GSI_NEW_STMT);
	else
		gsi_insert_after(gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
	return assign;
}

bool is_size_overflow_type(const_tree var)
{
	const char *name;
	const_tree type_name, type;

	if (var == NULL_TREE)
		return false;

	type = TREE_TYPE(var);
	type_name = TYPE_NAME(type);
	if (type_name == NULL_TREE)
		return false;

	if (DECL_P(type_name))
		name = DECL_NAME_POINTER(type_name);
	else
		name = IDENTIFIER_POINTER(type_name);

	if (!strncmp(name, "size_overflow_type", 18))
		return true;
	return false;
}

// Determine if a cloned function has all the original arguments
static bool unchanged_arglist(struct cgraph_node *new_node, struct cgraph_node *old_node)
{
	const_tree new_decl_list, old_decl_list;

	if (new_node->clone_of && new_node->clone.tree_map)
		return !new_node->clone.args_to_skip;

	new_decl_list = DECL_ARGUMENTS(NODE_DECL(new_node));
	old_decl_list = DECL_ARGUMENTS(NODE_DECL(old_node));
	if (new_decl_list != NULL_TREE && old_decl_list != NULL_TREE)
		gcc_assert(list_length(new_decl_list) == list_length(old_decl_list));

	return true;
}

unsigned int get_correct_argnum_fndecl(const_tree fndecl, const_tree correct_argnum_of_fndecl, unsigned int num)
{
	unsigned int new_num;
	const_tree fndecl_arg;
	tree fndecl_arglist = DECL_ARGUMENTS(fndecl);
	const_tree arg, target_fndecl_arglist;

	if (num == 0)
		return num;

	if (fndecl == correct_argnum_of_fndecl && !DECL_ARTIFICIAL(fndecl))
		return num;
	else if (fndecl == correct_argnum_of_fndecl && DECL_ARTIFICIAL(fndecl))
		return CANNOT_FIND_ARG;

	target_fndecl_arglist = DECL_ARGUMENTS(correct_argnum_of_fndecl);
	if (fndecl_arglist == NULL_TREE || target_fndecl_arglist == NULL_TREE)
		return CANNOT_FIND_ARG;

	fndecl_arg = chain_index(num - 1, fndecl_arglist);
	if (fndecl_arg == NULL_TREE)
		return CANNOT_FIND_ARG;

	for (arg = target_fndecl_arglist, new_num = 1; arg; arg = TREE_CHAIN(arg), new_num++) {
		if (arg == fndecl_arg || !strcmp(DECL_NAME_POINTER(arg), DECL_NAME_POINTER(fndecl_arg)))
			return new_num;
	}

	return CANNOT_FIND_ARG;
}

// Find the specified argument in the originally cloned function
static unsigned int clone_argnum_on_orig(struct cgraph_node *new_node, struct cgraph_node *old_node, unsigned int clone_argnum)
{
	bitmap args_to_skip;
	unsigned int i, new_argnum = clone_argnum;

	if (unchanged_arglist(new_node, old_node))
		return clone_argnum;

	gcc_assert(new_node->clone_of && new_node->clone.tree_map);
	args_to_skip = new_node->clone.args_to_skip;
	for (i = 0; i < clone_argnum; i++) {
		if (bitmap_bit_p(args_to_skip, i))
			new_argnum++;
	}
	return new_argnum;
}

// Find the specified argument in the clone
static unsigned int orig_argnum_on_clone(struct cgraph_node *new_node, struct cgraph_node *old_node, unsigned int orig_argnum)
{
	bitmap args_to_skip;
	unsigned int i, new_argnum = orig_argnum;

	if (unchanged_arglist(new_node, old_node))
		return orig_argnum;

	gcc_assert(new_node->clone_of && new_node->clone.tree_map);
	args_to_skip = new_node->clone.args_to_skip;
	if (bitmap_bit_p(args_to_skip, orig_argnum - 1))
		// XXX torolni kellene a nodeot
		return CANNOT_FIND_ARG;

	for (i = 0; i < orig_argnum; i++) {
		if (bitmap_bit_p(args_to_skip, i))
			new_argnum--;
	}
	return new_argnum;
}

// Associate the argument between a clone and a cloned function
static unsigned int get_correct_argnum_cnode(struct cgraph_node *node, struct cgraph_node *correct_argnum_of_node, unsigned int argnum)
{
	bool node_clone, correct_argnum_of_node_clone;
	const_tree correct_argnum_of_node_decl, node_decl;

	if (node == correct_argnum_of_node)
		return argnum;
	if (argnum == 0)
		return argnum;

	correct_argnum_of_node_decl = NODE_DECL(correct_argnum_of_node);
	gcc_assert(correct_argnum_of_node_decl != NULL_TREE);
	gcc_assert(correct_argnum_of_node && !DECL_ARTIFICIAL(correct_argnum_of_node_decl));

	if (node) {
		node_decl = NODE_DECL(node);
		gcc_assert(!DECL_ARTIFICIAL(node_decl));
		node_clone = made_by_compiler(node_decl);
	} else {
		node_decl = NULL_TREE;
		node_clone = false;
	}

	if (correct_argnum_of_node_decl == node_decl)
		return argnum;

	correct_argnum_of_node_clone = made_by_compiler(correct_argnum_of_node_decl);
	// the original decl is lost if both nodes are clones
	if (node_clone && correct_argnum_of_node_clone) {
		gcc_assert(unchanged_arglist(node, correct_argnum_of_node));
		return argnum;
	}

	if (node_clone && !correct_argnum_of_node_clone)
		return clone_argnum_on_orig(correct_argnum_of_node, node, argnum);
	else if (!node_clone && correct_argnum_of_node_clone)
		return orig_argnum_on_clone(correct_argnum_of_node, node, argnum);

	if (node)
		debug_tree(NODE_DECL(node));
	debug_tree(correct_argnum_of_node_decl);
	gcc_unreachable();
}

unsigned int get_correct_argnum(const_tree decl, const_tree correct_argnum_of_decl, unsigned int argnum)
{
	struct cgraph_node *node, *correct_argnum_of_node;

	gcc_assert(decl != NULL_TREE);
	gcc_assert(correct_argnum_of_decl != NULL_TREE);

	correct_argnum_of_node = get_cnode(correct_argnum_of_decl);
	if (!correct_argnum_of_node || DECL_ARTIFICIAL(decl) || DECL_ARTIFICIAL(correct_argnum_of_decl))
		return get_correct_argnum_fndecl(decl, correct_argnum_of_decl, argnum);

	node = get_cnode(decl);
	return get_correct_argnum_cnode(node, correct_argnum_of_node, argnum);
}

// Find the original cloned function
tree get_orig_fndecl(const_tree clone_fndecl)
{
	struct cgraph_node *node;

	gcc_assert(TREE_CODE(clone_fndecl) == FUNCTION_DECL);

	if (DECL_ABSTRACT_ORIGIN(clone_fndecl))
		return CONST_CAST_TREE(DECL_ABSTRACT_ORIGIN(clone_fndecl));
	node = get_cnode(clone_fndecl);
	if (!node)
		return CONST_CAST_TREE(clone_fndecl);

	while (node->clone_of)
		node = node->clone_of;
	if (!made_by_compiler(NODE_DECL(node)))
		return NODE_DECL(node);
	// Return the cloned decl because it is needed for the transform callback
	return CONST_CAST_TREE(clone_fndecl);
}

static tree get_interesting_fndecl_from_stmt(const gcall *stmt)
{
	if (gimple_call_num_args(stmt) == 0)
		return NULL_TREE;
	return gimple_call_fndecl(stmt);
}

tree get_interesting_orig_fndecl_from_stmt(const gcall *stmt)
{
	tree fndecl;

	fndecl = get_interesting_fndecl_from_stmt(stmt);
	if (fndecl == NULL_TREE)
		return NULL_TREE;
	return get_orig_fndecl(fndecl);
}

void set_dominance_info(void)
{
	calculate_dominance_info(CDI_DOMINATORS);
	calculate_dominance_info(CDI_POST_DOMINATORS);
}

void unset_dominance_info(void)
{
	free_dominance_info(CDI_DOMINATORS);
	free_dominance_info(CDI_POST_DOMINATORS);
}

void set_current_function_decl(tree fndecl)
{
	gcc_assert(fndecl != NULL_TREE);

	push_cfun(DECL_STRUCT_FUNCTION(fndecl));
#if BUILDING_GCC_VERSION <= 4007
	current_function_decl = fndecl;
#endif
	set_dominance_info();
}

void unset_current_function_decl(void)
{
	unset_dominance_info();
#if BUILDING_GCC_VERSION <= 4007
	current_function_decl = NULL_TREE;
#endif
	pop_cfun();
}

bool is_valid_cgraph_node(struct cgraph_node *node)
{
	if (cgraph_function_body_availability(node) == AVAIL_NOT_AVAILABLE)
		return false;
	if (node->thunk.thunk_p || node->alias)
		return false;
	return true;
}

tree get_lhs(const_gimple stmt)
{
	switch (gimple_code(stmt)) {
	case GIMPLE_ASSIGN:
	case GIMPLE_CALL:
		return gimple_get_lhs(stmt);
	case GIMPLE_PHI:
		return gimple_phi_result(stmt);
	default:
		debug_gimple_stmt((gimple)stmt);
		gcc_unreachable();
	}
}

