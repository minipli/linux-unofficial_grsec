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
#include <libgen.h>

static void walk_use_def_next_functions(struct walk_use_def_data *use_def_data, tree lhs);

next_interesting_function_t global_next_interesting_function[GLOBAL_NIFN_LEN];
static bool global_changed;

static struct cgraph_node_hook_list *function_insertion_hook_holder;
static struct cgraph_2node_hook_list *node_duplication_hook_holder;

struct cgraph_node *get_cnode(const_tree fndecl)
{
	gcc_assert(TREE_CODE(fndecl) == FUNCTION_DECL);
#if BUILDING_GCC_VERSION <= 4005
	return cgraph_get_node(CONST_CAST_TREE(fndecl));
#else
	return cgraph_get_node(fndecl);
#endif
}

static bool compare_next_interesting_functions(next_interesting_function_t cur_node, const char *decl_name, const char *context, unsigned int num)
{
	// Ignore num without a value
	if (num != NONE_ARGNUM && cur_node->num != num)
		return false;
	if (strcmp(cur_node->context, context))
		return false;
	return !strcmp(cur_node->decl_name, decl_name);
}

// Return the context of vardecl. If it is in a file scope then the context is vardecl_filebasename
static const char* get_vardecl_context(const_tree decl)
{
	expanded_location xloc;
	char *buf, *path;
	const char *bname;
	int len;

	xloc = expand_location(DECL_SOURCE_LOCATION(decl));
	gcc_assert(xloc.file);
	path = xstrdup(xloc.file);
	bname = basename(path);

	len = asprintf(&buf, "vardecl_%s", bname);
	gcc_assert(len > 0);
	return buf;
}

// Return the type name for a function pointer (or "fielddecl" if the type has no name), otherwise either "vardecl" or "fndecl"
const char* get_decl_context(const_tree decl)
{
	switch (TREE_CODE(decl)) {
	case FUNCTION_DECL:
		return "fndecl";
		// TODO: Ignore anonymous types for now
	case FIELD_DECL:
		return get_type_name_from_field(decl);
	case VAR_DECL:
		if (TREE_PUBLIC(decl) || DECL_EXTERNAL(decl))
			return "vardecl";
		if (TREE_STATIC(decl) && !TREE_PUBLIC(decl))
			return get_vardecl_context(decl);
		// ignore local variable
		if (!TREE_STATIC(decl) && !DECL_EXTERNAL(decl))
			return NULL;
	default:
		debug_tree(decl);
		gcc_unreachable();
	}
}

// Find the function with the specified argument in the list
next_interesting_function_t get_global_next_interesting_function_entry(struct fn_raw_data *raw_data)
{
	next_interesting_function_t cur_node, head;

	gcc_assert(raw_data->hash != NO_HASH);
	gcc_assert(raw_data->decl_str);
	gcc_assert(raw_data->context);

	head = global_next_interesting_function[raw_data->hash];
	for (cur_node = head; cur_node; cur_node = cur_node->next) {
		if (raw_data->marked != ASM_STMT_SO_MARK && cur_node->marked == ASM_STMT_SO_MARK)
			continue;
		if (compare_next_interesting_functions(cur_node, raw_data->decl_str, raw_data->context, raw_data->num))
			return cur_node;
	}
	return NULL;
}

next_interesting_function_t get_global_next_interesting_function_entry_with_hash(struct fn_raw_data *raw_data)
{
	gcc_assert(raw_data->decl != NULL_TREE);
	gcc_assert(raw_data->decl_str);

	raw_data->hash = get_decl_hash(raw_data->decl, raw_data->decl_str);
	if (raw_data->hash == NO_HASH)
		return NULL;

	if (!raw_data->context)
		raw_data->context = get_decl_context(raw_data->decl);
	if (!raw_data->context)
		return NULL;
	return get_global_next_interesting_function_entry(raw_data);
}

next_interesting_function_t create_new_next_interesting_entry(struct fn_raw_data *raw_data, next_interesting_function_t orig_next_node)
{
	next_interesting_function_t new_node;

	gcc_assert(raw_data->decl_str);
	gcc_assert(raw_data->context);
	gcc_assert(raw_data->hash != NO_HASH);
	gcc_assert(raw_data->num != NONE_ARGNUM);
	gcc_assert(raw_data->based_decl != SO_NONE);

	new_node = (next_interesting_function_t)xmalloc(sizeof(*new_node));
	new_node->decl_name = xstrdup(raw_data->decl_str);

	gcc_assert(raw_data->context);
	new_node->context = xstrdup(raw_data->context);
	new_node->hash = raw_data->hash;
	new_node->num = raw_data->num;
	new_node->next = NULL;
	new_node->children = NULL;
	new_node->marked = raw_data->marked;
	new_node->orig_next_node = orig_next_node;
	new_node->based_decl = raw_data->based_decl;

	return new_node;
}

// Ignore these functions to not explode coverage (+strncmp+fndecl+3+35130+)
static bool temporary_skip_these_functions(struct fn_raw_data *raw_data)
{
	gcc_assert(raw_data->hash != NO_HASH);
	gcc_assert(raw_data->decl_str);

	if (raw_data->hash == 35130 && !strcmp(raw_data->decl_str, "strncmp"))
		return true;
	if (raw_data->hash == 46193 && !strcmp(raw_data->decl_str, "strnlen"))
		return true;
	if (raw_data->hash == 43267 && !strcmp(raw_data->decl_str, "strncpy"))
		return true;
	if (raw_data->hash == 10300 && !strcmp(raw_data->decl_str, "strncpy_from_user"))
		return true;
	if (raw_data->hash == 26117 && !strcmp(raw_data->decl_str, "memchr"))
		return true;
	if (raw_data->hash == 16203 && !strcmp(raw_data->decl_str, "memchr_inv"))
		return true;
	if (raw_data->hash == 24269 && !strcmp(raw_data->decl_str, "memcmp"))
		return true;
	if (raw_data->hash == 60390 && !strcmp(raw_data->decl_str, "memcpy"))
		return true;
	if (raw_data->hash == 25040 && !strcmp(raw_data->decl_str, "memmove"))
		return true;
	if (raw_data->hash == 29763 && !strcmp(raw_data->decl_str, "memset"))
		return true;
	return false;
}

// Create the main data structure
next_interesting_function_t create_new_next_interesting_decl(struct fn_raw_data *raw_data, next_interesting_function_t orig_next_node)
{
	enum tree_code decl_code;

	if (raw_data->num == NONE_ARGNUM)
		return NULL;

	gcc_assert(raw_data->decl != NULL_TREE);
	gcc_assert(raw_data->num != NONE_ARGNUM);
	gcc_assert(raw_data->decl_str);

	decl_code = TREE_CODE(raw_data->decl);

	gcc_assert(decl_code == FIELD_DECL || decl_code == FUNCTION_DECL || decl_code == VAR_DECL);

	if (is_vararg(raw_data->decl, raw_data->num))
		return NULL;

	raw_data->hash = get_decl_hash(raw_data->decl, raw_data->decl_str);
	if (raw_data->hash == NO_HASH)
		return NULL;

	if (get_size_overflow_hash_entry_tree(raw_data, DISABLE_SIZE_OVERFLOW))
		return NULL;
	if (temporary_skip_these_functions(raw_data))
		return NULL;

	gcc_assert(raw_data->num <= MAX_PARAM);
	// Clones must have an orig_next_node
	gcc_assert(!made_by_compiler(raw_data->decl) || orig_next_node);

	raw_data->context = get_decl_context(raw_data->decl);
	if (!raw_data->context)
		return NULL;

	return create_new_next_interesting_entry(raw_data, orig_next_node);
}

void add_to_global_next_interesting_function(next_interesting_function_t new_entry)
{
	next_interesting_function_t cur_global_head, cur_global, cur_global_end = NULL;

	// new_entry is appended to the end of a list
	new_entry->next = NULL;

	cur_global_head = global_next_interesting_function[new_entry->hash];
	if (!cur_global_head) {
		global_next_interesting_function[new_entry->hash] = new_entry;
		return;
	}


	for (cur_global = cur_global_head; cur_global; cur_global = cur_global->next) {
		if (!cur_global->next)
			cur_global_end = cur_global;

		if (compare_next_interesting_functions(cur_global, new_entry->decl_name, new_entry->context, new_entry->num))
			return;
	}

	gcc_assert(cur_global_end);
	cur_global_end->next = new_entry;
}

/* If the interesting function is a clone then find or create its original next_interesting_function_t node
 * and add it to global_next_interesting_function
 */
static next_interesting_function_t create_orig_next_node_for_a_clone(struct fn_raw_data *clone_raw_data)
{
	struct fn_raw_data orig_raw_data;
	next_interesting_function_t orig_next_node;
	enum tree_code decl_code;

	gcc_assert(clone_raw_data->decl != NULL_TREE);
	gcc_assert(clone_raw_data->num != NONE_ARGNUM);
	gcc_assert(clone_raw_data->based_decl != SO_NONE);

	initialize_raw_data(&orig_raw_data);
	orig_raw_data.decl = get_orig_fndecl(clone_raw_data->decl);

	if (DECL_BUILT_IN(orig_raw_data.decl) || DECL_BUILT_IN_CLASS(orig_raw_data.decl) == BUILT_IN_NORMAL)
		return NULL;

	if (made_by_compiler(orig_raw_data.decl))
		return NULL;

	decl_code = TREE_CODE(orig_raw_data.decl);
	if (decl_code == FIELD_DECL || decl_code == VAR_DECL)
		orig_raw_data.num = clone_raw_data->num;
	else
		orig_raw_data.num = get_correct_argnum(clone_raw_data->decl, orig_raw_data.decl, clone_raw_data->num);

	// Skip over ISRA.162 parm decls
	if (orig_raw_data.num == CANNOT_FIND_ARG)
		return NULL;

	orig_raw_data.decl_str = get_orig_decl_name(orig_raw_data.decl);
	orig_raw_data.marked = NO_SO_MARK;
	orig_next_node = get_global_next_interesting_function_entry_with_hash(&orig_raw_data);
	if (orig_next_node)
		return orig_next_node;

	orig_raw_data.marked = clone_raw_data->marked;
	orig_raw_data.based_decl = clone_raw_data->based_decl;
	orig_next_node = create_new_next_interesting_decl(&orig_raw_data, NULL);
	if (!orig_next_node)
		return NULL;

	add_to_global_next_interesting_function(orig_next_node);
	return orig_next_node;
}

// Find or create the next_interesting_function_t node for decl and num
next_interesting_function_t get_and_create_next_node_from_global_next_nodes(struct fn_raw_data *raw_data, next_interesting_function_t orig_next_node)
{
	next_interesting_function_t cur_next_cnode;

	gcc_assert(raw_data->decl != NULL_TREE);

	if (DECL_NAME(raw_data->decl) == NULL_TREE)
		return NULL;

	raw_data->decl_str = DECL_NAME_POINTER(raw_data->decl);

	cur_next_cnode = get_global_next_interesting_function_entry_with_hash(raw_data);
	if (cur_next_cnode)
		goto out;

	if (!orig_next_node && made_by_compiler(raw_data->decl)) {
		orig_next_node = create_orig_next_node_for_a_clone(raw_data);
		if (!orig_next_node)
			return NULL;
	}

	cur_next_cnode = create_new_next_interesting_decl(raw_data, orig_next_node);
	if (!cur_next_cnode)
		return NULL;

	add_to_global_next_interesting_function(cur_next_cnode);
out:
	if (cur_next_cnode->marked != raw_data->marked && cur_next_cnode->marked != NO_SO_MARK)
		return cur_next_cnode;

	if (raw_data->marked != NO_SO_MARK && cur_next_cnode->marked == NO_SO_MARK)
		cur_next_cnode->marked = raw_data->marked;

	return cur_next_cnode;
}

static bool has_next_interesting_function_chain_node(next_interesting_function_t next_cnodes_head, struct fn_raw_data *raw_data)
{
	next_interesting_function_t cur_node;

	gcc_assert(!raw_data->context);

	gcc_assert(raw_data->decl_str);
	gcc_assert(raw_data->decl != NULL_TREE);
	gcc_assert(raw_data->num != NONE_ARGNUM);

	raw_data->context = get_decl_context(raw_data->decl);
	// Ignore function if there is no context
	if (!raw_data->context)
		return true;

	for (cur_node = next_cnodes_head; cur_node; cur_node = cur_node->next) {
		if (compare_next_interesting_functions(cur_node, raw_data->decl_str, raw_data->context, raw_data->num))
			return true;
	}
	return false;
}

static void handle_function(struct walk_use_def_data *use_def_data, tree fndecl, const_tree arg)
{
	struct fn_raw_data raw_data;
	next_interesting_function_t orig_next_node, new_node;

	gcc_assert(fndecl != NULL_TREE);

	// ignore builtins to not explode coverage (e.g., memcpy)
	if (DECL_BUILT_IN(fndecl) || DECL_BUILT_IN_CLASS(fndecl) == BUILT_IN_NORMAL)
		return;

	if (get_intentional_attr_type(fndecl) == MARK_TURN_OFF)
		return;

	initialize_raw_data(&raw_data);
	raw_data.decl = fndecl;
	raw_data.based_decl = SO_FUNCTION;
	raw_data.decl_str = DECL_NAME_POINTER(fndecl);
	raw_data.marked = NO_SO_MARK;

	// convert arg into its position
	if (arg == NULL_TREE)
		raw_data.num = 0;
	else
		raw_data.num = find_arg_number_tree(arg, raw_data.decl);
	if (raw_data.num == CANNOT_FIND_ARG)
		return;

	if (has_next_interesting_function_chain_node(use_def_data->next_cnodes_head, &raw_data))
		return;

	if (made_by_compiler(raw_data.decl)) {
		orig_next_node = create_orig_next_node_for_a_clone(&raw_data);
		if (!orig_next_node)
			return;
	} else
		orig_next_node = NULL;

	new_node = create_new_next_interesting_decl(&raw_data, orig_next_node);
	if (!new_node)
		return;
	new_node->next = use_def_data->next_cnodes_head;
	use_def_data->next_cnodes_head = new_node;
}

static void walk_use_def_next_functions_phi(struct walk_use_def_data *use_def_data, const_tree result)
{
	gphi *phi = as_a_gphi(get_def_stmt(result));
	unsigned int i, n = gimple_phi_num_args(phi);

	pointer_set_insert(use_def_data->visited, phi);
	for (i = 0; i < n; i++) {
		tree arg = gimple_phi_arg_def(phi, i);

		walk_use_def_next_functions(use_def_data, arg);
	}
}

static void walk_use_def_next_functions_binary(struct walk_use_def_data *use_def_data, const_tree lhs)
{
	gassign *def_stmt = as_a_gassign(get_def_stmt(lhs));
	tree rhs1, rhs2;

	rhs1 = gimple_assign_rhs1(def_stmt);
	rhs2 = gimple_assign_rhs2(def_stmt);

	walk_use_def_next_functions(use_def_data, rhs1);
	walk_use_def_next_functions(use_def_data, rhs2);
}

static void walk_use_def_next_functions_unary(struct walk_use_def_data *use_def_data, const gassign *stmt)
{
	tree rhs1 = gimple_assign_rhs1(stmt);

	walk_use_def_next_functions(use_def_data, rhs1);
}

void __weak handle_function_ptr_ret(struct walk_use_def_data *use_def_data __unused, const_tree fn_ptr __unused)
{
}

static void create_and_append_new_next_interesting_field_var_decl(struct walk_use_def_data *use_def_data, struct fn_raw_data *raw_data)
{
	next_interesting_function_t new_node;

	if (raw_data->decl == NULL_TREE)
		return;

	if (DECL_NAME(raw_data->decl) == NULL_TREE)
		return;

	gcc_assert(!raw_data->decl_str);
	gcc_assert(raw_data->num == NONE_ARGNUM);

	raw_data->decl_str = DECL_NAME_POINTER(raw_data->decl);
	raw_data->num = 0;
	raw_data->marked = NO_SO_MARK;

	new_node = create_new_next_interesting_decl(raw_data, NULL);
	if (!new_node)
		return;
	new_node->next = use_def_data->next_cnodes_head;
	use_def_data->next_cnodes_head = new_node;
}

static void handle_struct_fields(struct walk_use_def_data *use_def_data, const_tree node)
{
	struct fn_raw_data raw_data;

	initialize_raw_data(&raw_data);

	switch (TREE_CODE(node)) {
	case ARRAY_REF:
#if BUILDING_GCC_VERSION >= 4006
	case MEM_REF:
#endif
	case INDIRECT_REF:
	case COMPONENT_REF:
		raw_data.decl = get_ref_field(node);
		raw_data.based_decl = SO_FIELD;
		break;
	// TODO
	case BIT_FIELD_REF:
	case VIEW_CONVERT_EXPR:
	case REALPART_EXPR:
	case IMAGPART_EXPR:
		return;
	default:
		debug_tree(node);
		gcc_unreachable();
	}

	if (get_intentional_attr_type(raw_data.decl) == MARK_TURN_OFF)
		return;

	create_and_append_new_next_interesting_field_var_decl(use_def_data, &raw_data);
}

static void handle_vardecl(struct walk_use_def_data *use_def_data, tree node)
{
	struct fn_raw_data raw_data;

	initialize_raw_data(&raw_data);

	raw_data.decl = node;
	raw_data.based_decl = SO_VAR;
	create_and_append_new_next_interesting_field_var_decl(use_def_data, &raw_data);
}

/* Find all functions that influence lhs
 *
 * Encountered functions are added to the children vector (next_interesting_function_t).
 */
static void walk_use_def_next_functions(struct walk_use_def_data *use_def_data, tree lhs)
{
	enum tree_code code;
	const_gimple def_stmt;

	if (skip_types(lhs))
		return;

	if (VAR_P(lhs)) {
		handle_vardecl(use_def_data, lhs);
		return;
	}

	code = TREE_CODE(lhs);
	if (code == PARM_DECL) {
		handle_function(use_def_data, current_function_decl, lhs);
		return;
	}

	if (TREE_CODE_CLASS(code) == tcc_reference) {
		handle_struct_fields(use_def_data, lhs);
		return;
	}

	if (code != SSA_NAME)
		return;

	def_stmt = get_def_stmt(lhs);
	if (!def_stmt)
		return;

	if (pointer_set_insert(use_def_data->visited, def_stmt))
		return;

	switch (gimple_code(def_stmt)) {
	case GIMPLE_NOP:
		walk_use_def_next_functions(use_def_data, SSA_NAME_VAR(lhs));
		return;
	case GIMPLE_ASM:
		if (!is_size_overflow_asm(def_stmt))
			return;
		walk_use_def_next_functions(use_def_data, get_size_overflow_asm_input(as_a_const_gasm(def_stmt)));
		return;
	case GIMPLE_CALL: {
		tree fndecl = gimple_call_fndecl(def_stmt);

		if (fndecl != NULL_TREE) {
			handle_function(use_def_data, fndecl, NULL_TREE);
			return;
		}
		fndecl = gimple_call_fn(def_stmt);
		handle_function_ptr_ret(use_def_data, fndecl);
		return;
	}
	case GIMPLE_PHI:
		walk_use_def_next_functions_phi(use_def_data, lhs);
		return;
	case GIMPLE_ASSIGN:
		switch (gimple_num_ops(def_stmt)) {
		case 2:
			walk_use_def_next_functions_unary(use_def_data, as_a_const_gassign(def_stmt));
			return;
		case 3:
			walk_use_def_next_functions_binary(use_def_data, lhs);
			return;
		}
	default:
		debug_gimple_stmt((gimple)def_stmt);
		error("%s: unknown gimple code", __func__);
		gcc_unreachable();
	}
}

// Start the search for next_interesting_function_t children based on the (next_interesting_function_t) parent node
static next_interesting_function_t search_next_functions(tree node, next_interesting_function_t parent)
{
	struct walk_use_def_data use_def_data;

	use_def_data.parent = parent;
	use_def_data.next_cnodes_head = NULL;
	use_def_data.visited = pointer_set_create();

	walk_use_def_next_functions(&use_def_data, node);

	pointer_set_destroy(use_def_data.visited);
	return use_def_data.next_cnodes_head;
}

// True if child already exists in the next_interesting_function_t children vector
bool has_next_interesting_function_vec(next_interesting_function_t target, next_interesting_function_t next_node)
{
	unsigned int i;
	next_interesting_function_t cur;

	gcc_assert(next_node);
	// handle recursion
	if (!strcmp(target->decl_name, next_node->decl_name) && target->num == next_node->num)
		return true;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, target->children))
		return false;
	FOR_EACH_VEC_ELT(next_interesting_function_t, target->children, i, cur) {
#else
	FOR_EACH_VEC_SAFE_ELT(target->children, i, cur) {
#endif
		if (compare_next_interesting_functions(cur, next_node->decl_name, next_node->context, next_node->num))
			return true;
	}
	return false;
}

void push_child(next_interesting_function_t parent, next_interesting_function_t child)
{
	if (!has_next_interesting_function_vec(parent, child)) {
#if BUILDING_GCC_VERSION <= 4007
		VEC_safe_push(next_interesting_function_t, heap, parent->children, child);
#else
		vec_safe_push(parent->children, child);
#endif
	}
}

void __weak check_local_variables(next_interesting_function_t next_node __unused) {}

// Add children to parent and global_next_interesting_function
static void collect_data_for_execute(next_interesting_function_t parent, next_interesting_function_t children)
{
	next_interesting_function_t cur = children;

	gcc_assert(parent);

	while (cur) {
		struct fn_raw_data child_raw_data;
		next_interesting_function_t next, child;

		next = cur->next;

		initialize_raw_data(&child_raw_data);
		child_raw_data.decl_str = cur->decl_name;
		child_raw_data.context = cur->context;
		child_raw_data.hash = cur->hash;
		child_raw_data.num = cur->num;
		child_raw_data.marked = NO_SO_MARK;
		child = get_global_next_interesting_function_entry(&child_raw_data);
		if (!child) {
			add_to_global_next_interesting_function(cur);
			child = cur;
		}

		check_local_variables(child);

		push_child(parent, child);

		cur = next;
	}

	check_local_variables(parent);
}

next_interesting_function_t __weak get_and_create_next_node_from_global_next_nodes_fnptr(const_tree fn_ptr __unused, struct fn_raw_data *raw_data __unused)
{
	return NULL;
}

static next_interesting_function_t create_parent_next_cnode(const_gimple stmt, unsigned int num)
{
	struct fn_raw_data raw_data;

	initialize_raw_data(&raw_data);
	raw_data.num = num;
	raw_data.marked = NO_SO_MARK;
	raw_data.based_decl = SO_FUNCTION;

	switch (gimple_code(stmt)) {
	case GIMPLE_ASM:
		raw_data.decl = current_function_decl;
		raw_data.marked = ASM_STMT_SO_MARK;
		return get_and_create_next_node_from_global_next_nodes(&raw_data, NULL);
	case GIMPLE_CALL:
		raw_data.decl = gimple_call_fndecl(stmt);
		if (raw_data.decl != NULL_TREE)
			return get_and_create_next_node_from_global_next_nodes(&raw_data, NULL);
		raw_data.decl = gimple_call_fn(stmt);
		return get_and_create_next_node_from_global_next_nodes_fnptr(raw_data.decl, &raw_data);
	case GIMPLE_RETURN:
		raw_data.decl = current_function_decl;
		return get_and_create_next_node_from_global_next_nodes(&raw_data, NULL);
	case GIMPLE_ASSIGN: {
		tree lhs = gimple_assign_lhs(stmt);

		if (VAR_P(lhs))
			raw_data.decl = lhs;
		else
			raw_data.decl = get_ref_field(lhs);
		if (raw_data.decl == NULL_TREE)
			return NULL;
		return get_and_create_next_node_from_global_next_nodes(&raw_data, NULL);
	}
	default:
		debug_gimple_stmt((gimple)stmt);
		gcc_unreachable();
	}
}

// Handle potential next_interesting_function_t parent if its argument has an integer type
static void collect_all_possible_size_overflow_fns(const_gimple stmt, tree start_var, unsigned int num)
{
	next_interesting_function_t children_next_cnode, parent_next_cnode;

	// skip void return values
	if (start_var == NULL_TREE)
		return;

	if (skip_types(start_var))
		return;

	// handle intentional MARK_TURN_OFF
	if (check_intentional_size_overflow_asm_and_attribute(start_var) == MARK_TURN_OFF)
		return;

	parent_next_cnode = create_parent_next_cnode(stmt, num);
	if (!parent_next_cnode)
		return;

	children_next_cnode = search_next_functions(start_var, parent_next_cnode);
	collect_data_for_execute(parent_next_cnode, children_next_cnode);
}

static void collect_all_possible_size_overflow_fields_and_vars(const gassign *assign)
{
	tree start_var, decl, lhs = gimple_assign_lhs(assign);

	if (VAR_P(lhs))
		decl = lhs;
	else
		decl = get_ref_field(lhs);
	if (decl == NULL_TREE)
		return;

	if (get_intentional_attr_type(decl) == MARK_TURN_OFF)
		return;

	start_var = gimple_assign_rhs1(assign);
	collect_all_possible_size_overflow_fns(assign, start_var, 0);

	start_var = gimple_assign_rhs2(assign);
	collect_all_possible_size_overflow_fns(assign, start_var, 0);

#if BUILDING_GCC_VERSION >= 4006
	start_var = gimple_assign_rhs3(assign);
	collect_all_possible_size_overflow_fns(assign, start_var, 0);
#endif
}

// Find potential next_interesting_function_t parents
static void handle_cgraph_node(struct cgraph_node *node)
{
	basic_block bb;
	tree cur_fndecl = NODE_DECL(node);

	set_current_function_decl(cur_fndecl);

	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			tree start_var;
			gimple stmt = gsi_stmt(gsi);

			switch (gimple_code(stmt)) {
			case GIMPLE_RETURN: {
				const greturn *return_stmt = as_a_const_greturn(stmt);

				start_var = gimple_return_retval(return_stmt);
				collect_all_possible_size_overflow_fns(return_stmt, start_var, 0);
				break;
			}
			case GIMPLE_ASM: {
				const gasm *asm_stmt = as_a_const_gasm(stmt);

				if (!is_size_overflow_insert_check_asm(asm_stmt))
					break;
				start_var = get_size_overflow_asm_input(asm_stmt);
				collect_all_possible_size_overflow_fns(asm_stmt, start_var, 0);
				break;
			}
			case GIMPLE_CALL: {
				unsigned int i, len;
				const gcall *call = as_a_const_gcall(stmt);
				tree fndecl = gimple_call_fndecl(call);

				if (fndecl != NULL_TREE && (DECL_BUILT_IN(fndecl) || DECL_BUILT_IN_CLASS(fndecl) == BUILT_IN_NORMAL))
					break;

				len = gimple_call_num_args(call);
				for (i = 0; i < len; i++) {
					start_var = gimple_call_arg(call, i);
					collect_all_possible_size_overflow_fns(call, start_var, i + 1);
				}
				break;
			}
			case GIMPLE_ASSIGN:
				collect_all_possible_size_overflow_fields_and_vars(as_a_const_gassign(stmt));
				break;
			default:
				break;
			}
		}
	}

	unset_current_function_decl();
}

/* Collect all potentially interesting function parameters and return values of integer types
 * and store their data flow dependencies
 */
static void size_overflow_generate_summary(void)
{
	struct cgraph_node *node;

	size_overflow_register_hooks();

	FOR_EACH_FUNCTION(node) {
		if (is_valid_cgraph_node(node))
			handle_cgraph_node(node);
	}
}

static void size_overflow_function_insertion_hook(struct cgraph_node *node __unused, void *data __unused)
{
	debug_cgraph_node(node);
	gcc_unreachable();
}

/* Handle dst if src is in the global_next_interesting_function list.
 * If src is a clone then dst inherits the orig_next_node of src otherwise
 * src will become the orig_next_node of dst.
 */
static void size_overflow_node_duplication_hook(struct cgraph_node *src, struct cgraph_node *dst, void *data __unused)
{
	next_interesting_function_t head, cur;
	struct fn_raw_data src_raw_data;

	initialize_raw_data(&src_raw_data);
	src_raw_data.decl = NODE_DECL(src);
	src_raw_data.decl_str = DECL_NAME_POINTER(src_raw_data.decl);
	src_raw_data.context = get_decl_context(src_raw_data.decl);
	if (!src_raw_data.context)
		return;

	src_raw_data.num = NONE_ARGNUM;
	src_raw_data.marked = NO_SO_MARK;

	head = get_global_next_interesting_function_entry_with_hash(&src_raw_data);
	if (!head)
		return;

	for (cur = head; cur; cur = cur->next) {
		struct fn_raw_data dst_raw_data;
		next_interesting_function_t orig_next_node, next_node;

		if (!compare_next_interesting_functions(cur, src_raw_data.decl_str, src_raw_data.context, src_raw_data.num))
			continue;

		initialize_raw_data(&dst_raw_data);
		dst_raw_data.decl = NODE_DECL(dst);
		dst_raw_data.decl_str = cgraph_node_name(dst);
		dst_raw_data.marked = cur->marked;
		dst_raw_data.based_decl = cur->based_decl;

		if (!made_by_compiler(dst_raw_data.decl))
			break;

		// For clones use the original node instead
		if (cur->orig_next_node)
			orig_next_node = cur->orig_next_node;
		else
			orig_next_node = cur;

		dst_raw_data.num = get_correct_argnum_fndecl(src_raw_data.decl, dst_raw_data.decl, cur->num);
		if (dst_raw_data.num == CANNOT_FIND_ARG)
			continue;

		next_node = create_new_next_interesting_decl(&dst_raw_data, orig_next_node);
		if (next_node)
			add_to_global_next_interesting_function(next_node);
	}
}

void size_overflow_register_hooks(void)
{
	static bool init_p = false;

	if (init_p)
		return;
	init_p = true;

	function_insertion_hook_holder = cgraph_add_function_insertion_hook(&size_overflow_function_insertion_hook, NULL);
	node_duplication_hook_holder = cgraph_add_node_duplication_hook(&size_overflow_node_duplication_hook, NULL);
}

static void set_yes_so_mark(next_interesting_function_t next_node)
{
	if (next_node->marked == NO_SO_MARK) {
		next_node->marked = YES_SO_MARK;
		global_changed = true;
	}
	// Mark the orig decl as well if it's a clone
	if (next_node->orig_next_node && next_node->orig_next_node->marked == NO_SO_MARK) {
		next_node->orig_next_node->marked = YES_SO_MARK;
		global_changed = true;
	}
}

// Determine whether node or orig node is part of a tracked data flow
static bool marked_fn(next_interesting_function_t next_node)
{
	bool is_marked_fn, is_marked_orig = false;

	is_marked_fn = next_node->marked != NO_SO_MARK;

	if (next_node->orig_next_node)
		is_marked_orig = next_node->orig_next_node->marked != NO_SO_MARK;

	return is_marked_fn || is_marked_orig;
}

// Determine whether node or orig node is in the hash table already
static bool already_in_the_hashtable(next_interesting_function_t next_node)
{
	struct fn_raw_data raw_data;

	if (next_node->orig_next_node)
		next_node = next_node->orig_next_node;

	initialize_raw_data(&raw_data);
	raw_data.context = next_node->context;
	raw_data.orig_decl_str = next_node->decl_name;
	raw_data.orig_num = next_node->num;
	raw_data.hash = next_node->hash;

	return get_size_overflow_hash_entry(&raw_data) != NULL;
}

// Propagate the size_overflow marks up the use-def chains
static bool has_marked_child(next_interesting_function_t next_node)
{
	bool ret = false;
	unsigned int i;
	next_interesting_function_t child;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, next_node->children))
		return false;
	FOR_EACH_VEC_ELT(next_interesting_function_t, next_node->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(next_node->children, i, child) {
#endif
		if (marked_fn(child) || already_in_the_hashtable(child))
			ret = true;
	}

	return ret;
}

/* Set YES_SO_MARK on the function, its orig node and children if:
 *      * the function or its orig node or one of its children is in the hash table already
 *      * the function's orig node is marked with YES_SO_MARK or ASM_STMT_SO_MARK
 *      * one of the children is marked with YES_SO_MARK or ASM_STMT_SO_MARK
 */
static bool set_fn_so_mark(next_interesting_function_t next_node)
{
	bool so_fn, so_hashtable, so_child;

	so_hashtable = already_in_the_hashtable(next_node);
	so_fn = marked_fn(next_node);
	so_child = has_marked_child(next_node);

	if (!so_fn && !so_hashtable && !so_child)
		return false;
	set_yes_so_mark(next_node);
	return true;
}

// Determine if any of the function pointer targets have data flow between the return value and one of the arguments
static next_interesting_function_t get_same_not_ret_child(next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return NULL;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		if (child->num == 0)
			continue;
		if (strcmp(parent->decl_name, child->decl_name))
			continue;
		if (!strcmp(child->context, "fndecl"))
			return child;
	}
	return NULL;
}

/* Trace a return value of function pointer type back to an argument via a concrete function
   fnptr 0 && fn 0 && (fn 0 -> fn 2) => fnptr 2 */
static void search_missing_fptr_arg(next_interesting_function_t parent)
{
	next_interesting_function_t child;
	unsigned int i;
#if BUILDING_GCC_VERSION <= 4007
	VEC(next_interesting_function_t, heap) *new_children = NULL;
#else
	vec<next_interesting_function_t, va_heap, vl_embed> *new_children = NULL;
#endif

	if (parent->num != 0)
		return;
	if (!strcmp(parent->context, "fndecl"))
		return;
	if (!strncmp(parent->context, "vardecl", sizeof("vardecl") - 1))
		return;

	// fnptr 0 && fn 0
#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		next_interesting_function_t cur_next_node, tracked_fn;

		if (child->num != 0)
			continue;
		// (fn 0 -> fn 2)
		tracked_fn = get_same_not_ret_child(child);
		if (!tracked_fn)
			continue;

		// fn 2 => fnptr 2
		for (cur_next_node = global_next_interesting_function[parent->hash]; cur_next_node; cur_next_node = cur_next_node->next) {
			if (cur_next_node->num != tracked_fn->num)
				continue;

			if (strcmp(parent->decl_name, cur_next_node->decl_name))
				continue;

			if (!has_next_interesting_function_vec(parent, cur_next_node)) {
#if BUILDING_GCC_VERSION <= 4007
				VEC_safe_push(next_interesting_function_t, heap, new_children, cur_next_node);
#else
				vec_safe_push(new_children, cur_next_node);
#endif
			}
		}
	}

#if BUILDING_GCC_VERSION == 4005
	if (VEC_empty(next_interesting_function_t, new_children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, new_children, i, child)
		VEC_safe_push(next_interesting_function_t, heap, parent->children, child);
#elif BUILDING_GCC_VERSION <= 4007
	VEC_safe_splice(next_interesting_function_t, heap, parent->children, new_children);
#else
	vec_safe_splice(parent->children, new_children);
#endif
}

static void walk_so_marked_fns(next_interesting_function_set *visited, next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

	gcc_assert(parent);
	if (!set_fn_so_mark(parent))
		return;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		set_yes_so_mark(child);

		if (!pointer_set_insert(visited, child))
			walk_so_marked_fns(visited, child);
	}
}

// Do a depth-first recursive dump of the next_interesting_function_t children vector
static void print_missing_functions(next_interesting_function_set *visited, next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

	gcc_assert(parent);
	gcc_assert(parent->marked != NO_SO_MARK);
	print_missing_function(parent);

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		gcc_assert(child->marked != NO_SO_MARK);
		if (!pointer_set_insert(visited, child))
			print_missing_functions(visited, child);
	}
}

// Set YES_SO_MARK on functions that will be emitted into the hash table
static void search_so_marked_fns(void)
{

	unsigned int i;
	next_interesting_function_set *visited;

	visited = next_interesting_function_pointer_set_create();
	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		next_interesting_function_t cur_global;

		for (cur_global = global_next_interesting_function[i]; cur_global; cur_global = cur_global->next) {
			if (cur_global->marked != NO_SO_MARK && !pointer_set_insert(visited, cur_global))
				walk_so_marked_fns(visited, cur_global);
		}
	}
	pointer_set_destroy(visited);
}

static void walk_marked_functions(next_interesting_function_set *visited, next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

	if (pointer_set_insert(visited, parent))
		return;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		switch (parent->based_decl) {
		case SO_FIELD:
			child->based_decl = SO_FIELD;
			gcc_assert(child->based_decl != SO_FUNCTION_POINTER);
			break;
		case SO_FUNCTION_POINTER:
			child->based_decl = SO_FUNCTION_POINTER;
			gcc_assert(child->based_decl != SO_FIELD);
			break;
		case SO_FUNCTION:
		case SO_VAR:
			break;
		default:
			gcc_unreachable();
		}

		walk_marked_functions(visited, child);
	}
}

static void set_based_decl(void)
{
	unsigned int i;
	next_interesting_function_set *visited;

	visited = next_interesting_function_pointer_set_create();
	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		next_interesting_function_t cur;

		for (cur = global_next_interesting_function[i]; cur; cur = cur->next) {
			if (cur->marked == ASM_STMT_SO_MARK && !pointer_set_contains(visited, cur))
				walk_marked_functions(visited, cur);
		}
	}
	pointer_set_destroy(visited);
}

// Print functions missing from the hash table
static void print_so_marked_fns(void)
{
	unsigned int i;
	next_interesting_function_set *visited;

	visited = next_interesting_function_pointer_set_create();
	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		next_interesting_function_t cur_global;

		for (cur_global = global_next_interesting_function[i]; cur_global; cur_global = cur_global->next) {
			if (cur_global->marked != NO_SO_MARK && !pointer_set_insert(visited, cur_global))
				print_missing_functions(visited, cur_global);
		}
	}
	pointer_set_destroy(visited);
}

void __weak check_global_variables(next_interesting_function_t cur_global __unused) {}

static void global_vars_and_fptrs(void)
{
	unsigned int i;

	if (!in_lto_p)
		return;

	// Collect vardecls and funtions reachable by function pointers
	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		next_interesting_function_t cur_global;

		for (cur_global = global_next_interesting_function[i]; cur_global; cur_global = cur_global->next) {
			check_global_variables(cur_global);
			search_missing_fptr_arg(cur_global);
		}
	}
}

static void print_parent_child(next_interesting_function_set *visited, next_interesting_function_t parent)
{
	unsigned int i;
	next_interesting_function_t child;

#if BUILDING_GCC_VERSION <= 4007
	if (VEC_empty(next_interesting_function_t, parent->children))
		return;
	FOR_EACH_VEC_ELT(next_interesting_function_t, parent->children, i, child) {
#else
	FOR_EACH_VEC_SAFE_ELT(parent->children, i, child) {
#endif
		fprintf(stderr, " PARENT: decl: %s-%u context: %s %p\n", parent->decl_name, parent->num, parent->context, parent);
		fprintf(stderr, " \tCHILD: decl: %s-%u context: %s %p\n", child->decl_name, child->num, child->context, child);

		if (!pointer_set_insert(visited, child))
			print_parent_child(visited, child);
	}
}

static void print_data_flow(void)
{
	unsigned int i;
	next_interesting_function_set *visited;

	if (!in_lto_p)
		return;

	visited = next_interesting_function_pointer_set_create();
	for (i = 0; i < GLOBAL_NIFN_LEN; i++) {
		next_interesting_function_t cur_global;

		for (cur_global = global_next_interesting_function[i]; cur_global; cur_global = cur_global->next) {
			if (cur_global->marked == NO_SO_MARK || pointer_set_insert(visited, cur_global))
				continue;

			fprintf(stderr, "Data flow: decl: %s-%u context: %s %p\n", cur_global->decl_name, cur_global->num, cur_global->context, cur_global);

			print_parent_child(visited, cur_global);

			fprintf(stderr, "\n");
		}
	}
	pointer_set_destroy(visited);
}

static void set_so_fns(void)
{
	do {
		global_changed = false;
		search_so_marked_fns();
	} while (global_changed);

	print_data_flow();
}

// Print all missing interesting functions
static unsigned int size_overflow_execute(void)
{
	if (flag_lto && !in_lto_p)
		return 0;

	global_vars_and_fptrs();

	set_so_fns();
	set_based_decl();
	print_so_marked_fns();

	if (in_lto_p) {
		fprintf(stderr, "%s: SIZE_OVERFLOW EXECUTE\n", __func__);
		print_global_next_interesting_functions();
	}

	return 0;
}

// Omit the IPA/LTO callbacks until https://gcc.gnu.org/bugzilla/show_bug.cgi?id=61311 gets fixed (license concerns)
#if BUILDING_GCC_VERSION >= 4008
void __weak size_overflow_write_summary(void) {}
void __weak size_overflow_write_optimization_summary(void) {}
#elif BUILDING_GCC_VERSION >= 4006
void __weak size_overflow_write_summary(cgraph_node_set set __unused, varpool_node_set vset __unused) {}
void __weak size_overflow_write_optimization_summary(cgraph_node_set set __unused, varpool_node_set vset __unused) {}
#else
void __weak size_overflow_write_summary(cgraph_node_set set __unused) {}
void __weak size_overflow_write_optimization_summary(cgraph_node_set set __unused) {}
#endif

void __weak size_overflow_read_summary(void);
void __weak size_overflow_read_optimization_summary(void);

#define PASS_NAME size_overflow

#define NO_STMT_FIXUP
#define NO_VARIABLE_TRANSFORM
#define NO_GATE

#include "gcc-generate-ipa-pass.h"
