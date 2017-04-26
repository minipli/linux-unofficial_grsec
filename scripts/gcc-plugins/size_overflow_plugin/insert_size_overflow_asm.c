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

// Data for the size_overflow asm stmt
struct asm_data {
	// call or return stmt with our attributes
	gimple target_stmt;
	// def_stmt of the marked arg
	gimple def_stmt;
	// size_overflow asm rhs
	tree input;
	// the output (lhs) of the size_overflow asm is the marked arg
	tree output;
	// marked arg number (0 for return values)
	unsigned int argnum;
	// intentional mark type
	enum intentional_mark intentional_mark;
};

static void __unused print_asm_data(struct asm_data *asm_data)
{
	fprintf(stderr, "-----------------------\nprint_asm_data:\n");

	fprintf(stderr, "def_stmt\n");
	debug_gimple_stmt(asm_data->def_stmt);
	fprintf(stderr, "target_stmt\n");
	debug_gimple_stmt(asm_data->target_stmt);
	fprintf(stderr, "output\n");
	debug_tree(asm_data->output);
	fprintf(stderr, "input\n");
	debug_tree(asm_data->input);
}

static const char *convert_mark_to_str(enum intentional_mark mark)
{
	switch (mark) {
	case MARK_NO:
		return OK_ASM_STR;
	case MARK_YES:
		return YES_ASM_STR;
	case MARK_END_INTENTIONAL:
		return END_INTENTIONAL_ASM_STR;
	case MARK_TURN_OFF:
		return TURN_OFF_ASM_STR;
	}
	gcc_unreachable();
}

static char *create_asm_comment(struct asm_data *asm_data, const char *mark_str)
{
	const char *fn_name;
	char *asm_comment;
	unsigned int len;

	if (gimple_code(asm_data->target_stmt) == GIMPLE_RETURN)
		fn_name = DECL_NAME_POINTER(current_function_decl);
	else
		fn_name = DECL_NAME_POINTER(gimple_call_fndecl(asm_data->target_stmt));

	len = asprintf(&asm_comment, "%s %s %u", mark_str, fn_name, asm_data->argnum);
	gcc_assert(len > 0);

	return asm_comment;
}

#if BUILDING_GCC_VERSION <= 4007
static VEC(tree, gc) *create_asm_io_list(tree string, tree io)
#else
static vec<tree, va_gc> *create_asm_io_list(tree string, tree io)
#endif
{
	tree list;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, gc) *vec_list = NULL;
#else
	vec<tree, va_gc> *vec_list = NULL;
#endif

	list = build_tree_list(NULL_TREE, string);
	list = chainon(NULL_TREE, build_tree_list(list, io));
#if BUILDING_GCC_VERSION <= 4007
	VEC_safe_push(tree, gc, vec_list, list);
#else
	vec_safe_push(vec_list, list);
#endif
	return vec_list;
}

static void create_so_asm_stmt(struct asm_data *asm_data)
{
	char *asm_comment;
	const char *mark_str;
	gasm *asm_stmt;
	gimple_stmt_iterator gsi;
	tree str_input, str_output;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, gc) *input = NULL, *output = NULL;
#else
	vec<tree, va_gc> *input = NULL, *output = NULL;
#endif

	mark_str = convert_mark_to_str(asm_data->intentional_mark);
	asm_comment = create_asm_comment(asm_data, mark_str);

	str_input = build_const_char_string(2, "0");
	input = create_asm_io_list(str_input, asm_data->input);
	str_output = build_const_char_string(4, "=rm");
	output = create_asm_io_list(str_output, asm_data->output);

	asm_stmt = as_a_gasm(gimple_build_asm_vec(asm_comment, input, output, NULL, NULL));
	gimple_asm_set_volatile(asm_stmt, true);

	gsi = gsi_for_stmt(asm_data->def_stmt);
	gsi_insert_after(&gsi, asm_stmt, GSI_NEW_STMT);

	SSA_NAME_DEF_STMT(asm_data->output) = asm_stmt;

	free(asm_comment);
}

static void check_size_overflow_asm(struct asm_data *asm_data)
{
	enum intentional_mark old_intentional_mark = get_so_asm_type(asm_data->def_stmt);

	if (old_intentional_mark == asm_data->intentional_mark)
		return;
	if (asm_data->intentional_mark == MARK_NO)
		return;

	print_intentional_mark(old_intentional_mark);
	print_intentional_mark(asm_data->intentional_mark);
	gcc_unreachable();
}

static tree get_so_asm_output(struct asm_data *asm_data)
{
	gimple stmt = asm_data->target_stmt;
	unsigned int argnum = asm_data->argnum;

	switch (gimple_code(stmt)) {
	case GIMPLE_RETURN:
		gcc_assert(argnum == 0);
		return gimple_return_retval(as_a_greturn(stmt));
	case GIMPLE_CALL:
		gcc_assert(argnum != 0);
		gcc_assert(gimple_call_num_args(stmt) >= argnum);
		return gimple_call_arg(stmt, argnum - 1);
	default:
		debug_gimple_stmt(stmt);
		gcc_unreachable();
	}
}

static tree get_so_asm_input(struct asm_data *asm_data)
{
	gassign *assign;
	tree output_type, new_var;
	gimple_stmt_iterator gsi;

	output_type = TREE_TYPE(asm_data->output);
	new_var = create_new_var(output_type);

	assign = gimple_build_assign(new_var, asm_data->output);
	gimple_assign_set_lhs(assign, make_ssa_name(new_var, assign));

	gsi = gsi_for_stmt(asm_data->target_stmt);
	gsi_insert_before(&gsi, assign, GSI_NEW_STMT);

	asm_data->def_stmt = assign;

	new_var = create_new_var(output_type);
	asm_data->output = make_ssa_name(new_var, asm_data->target_stmt);

	return gimple_assign_lhs(assign);
}

static void set_so_asm_input_target_stmt(struct asm_data *asm_data)
{
	switch (gimple_code(asm_data->target_stmt)) {
	case GIMPLE_CALL:
		gimple_call_set_arg(asm_data->target_stmt, asm_data->argnum - 1, asm_data->output);
		break;
	case GIMPLE_RETURN:
		gimple_return_set_retval(as_a_greturn(asm_data->target_stmt), asm_data->output);
		break;
	default:
		debug_gimple_stmt(asm_data->target_stmt);
		gcc_unreachable();
	}

	update_stmt(asm_data->def_stmt);
}

/* This is the gimple part of searching for a missing size_overflow attribute. If the intentional_overflow attribute type
 * is of the right kind create the appropriate size_overflow asm stmts:
 *   __asm__("# size_overflow MARK_END_INTENTIONAL" : =rm" D.3344_8 : "0" cicus.4_16);
 *   __asm__("# size_overflow MARK_NO" : =rm" cicus.4_16 : "0" size_1(D));
 */
static void __insert_size_overflow_asm(gimple stmt, unsigned int argnum, enum intentional_mark intentional_mark)
{
	struct asm_data asm_data;

	asm_data.target_stmt = stmt;
	asm_data.argnum = argnum;
	asm_data.intentional_mark = intentional_mark;

	asm_data.output = get_so_asm_output(&asm_data);
	if (asm_data.output == NULL_TREE)
		return;
	if (is_gimple_constant(asm_data.output))
		return;
	if (skip_types(asm_data.output))
		return;

	asm_data.def_stmt = get_def_stmt(asm_data.output);
	if (is_size_overflow_asm(asm_data.def_stmt)) {
		check_size_overflow_asm(&asm_data);
		return;
	}

	asm_data.input = get_so_asm_input(&asm_data);

	create_so_asm_stmt(&asm_data);
	set_so_asm_input_target_stmt(&asm_data);

	update_stmt(asm_data.def_stmt);
	update_stmt(asm_data.target_stmt);
}

// Determine the correct arg index and arg and insert the asm stmt to mark the stmt.
static void insert_so_asm_by_so_attr(gimple stmt, unsigned int orig_argnum)
{
	if (orig_argnum == 0 && gimple_code(stmt) == GIMPLE_RETURN) {
		__insert_size_overflow_asm(stmt, 0, MARK_NO);
		return;
	}

	if (orig_argnum != 0 && gimple_code(stmt) == GIMPLE_CALL)
		__insert_size_overflow_asm(stmt, orig_argnum, MARK_NO);
}

// If a function arg or the return value is marked by the size_overflow attribute then set its index in the array.
static void set_argnum_attribute(const_tree attr, bool *argnums)
{
	unsigned int argnum;
	tree attr_value;

	gcc_assert(attr);
	for (attr_value = TREE_VALUE(attr); attr_value; attr_value = TREE_CHAIN(attr_value)) {
		argnum = (unsigned int)tree_to_uhwi(TREE_VALUE(attr_value));
		argnums[argnum] = true;
	}
}

// Check whether the arguments are marked by the size_overflow attribute.
static void search_interesting_so_args(tree fndecl, bool *argnums)
{
	const_tree attr;

	attr = get_attribute("size_overflow", fndecl);
	if (attr)
		set_argnum_attribute(attr, argnums);
}

static enum intentional_mark handle_intentional_attr(gimple stmt, unsigned int argnum)
{
	enum intentional_mark mark;
	struct fn_raw_data raw_data;

	mark = check_intentional_attribute(stmt, argnum);
	if (mark == MARK_NO)
		return MARK_NO;

	initialize_raw_data(&raw_data);
	raw_data.num = argnum;

	if (gimple_code(stmt) == GIMPLE_RETURN)
		raw_data.decl = current_function_decl;
	else
		raw_data.decl = gimple_call_fndecl(stmt);

	if (raw_data.decl == NULL_TREE && !get_size_overflow_hash_entry_tree(&raw_data, DISABLE_SIZE_OVERFLOW))
		return MARK_NO;
	__insert_size_overflow_asm(stmt, argnum, mark);
	return mark;
}

static void handle_size_overflow_attr_ret(greturn *stmt)
{
	enum intentional_mark mark;
	bool orig_argnums[MAX_PARAM + 1] = {false};

	search_interesting_so_args(get_orig_fndecl(current_function_decl), (bool *) &orig_argnums);

	mark = handle_intentional_attr(stmt, 0);
	if (mark == MARK_NO && orig_argnums[0])
		insert_so_asm_by_so_attr(stmt, 0);
}

// If the argument(s) of the callee function are marked by an attribute then mark the call stmt with an asm stmt
static void handle_size_overflow_attr_call(gcall *stmt)
{
	tree fndecl;
	unsigned int argnum;
	bool orig_argnums[MAX_PARAM + 1] = {false};

	fndecl = get_interesting_orig_fndecl_from_stmt(stmt);
	if (fndecl == NULL_TREE)
		return;
	if (DECL_BUILT_IN(fndecl))
		return;

	search_interesting_so_args(fndecl, (bool *) &orig_argnums);

	for (argnum = 1; argnum <= gimple_call_num_args(stmt); argnum++) {
		enum intentional_mark mark = handle_intentional_attr(stmt, argnum);

		if (mark == MARK_NO && !is_vararg(fndecl, argnum) && orig_argnums[argnum])
			insert_so_asm_by_so_attr(stmt, argnum);
	}
}

// Iterate over all the stmts and search for call stmts and mark them if they have size_overflow attribute
static unsigned int insert_size_overflow_asm_execute(void)
{
	basic_block bb;

	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			gimple stmt = gsi_stmt(gsi);

			if (is_gimple_call(stmt))
				handle_size_overflow_attr_call(as_a_gcall(stmt));
			else if (gimple_code(stmt) == GIMPLE_RETURN)
				handle_size_overflow_attr_ret(as_a_greturn(stmt));
		}
	}
	return 0;
}

/*
 * A lot of functions get inlined before the ipa passes so after the build_ssa gimple pass
 * this pass inserts asm stmts to mark the interesting args
 * that the ipa pass will detect and insert the size overflow checks for.
 */

#define PASS_NAME insert_size_overflow_asm

#define NO_GATE

#define PROPERTIES_REQUIRED PROP_cfg
#define TODO_FLAGS_FINISH TODO_dump_func | TODO_verify_ssa | TODO_verify_stmts | TODO_remove_unused_locals | TODO_update_ssa_no_phi | TODO_cleanup_cfg | TODO_ggc_collect | TODO_verify_flow

#include "gcc-generate-gimple-pass.h"
