/*
 * Copyright 2011-2017 by the PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to implement various sparse (source code checker) features
 *
 * TODO:
 * - define separate __iomem, __percpu and __rcu address spaces (lots of code to patch)
 *
 * BUGS:
 * - none known
 */

#include "gcc-common.h"

extern void c_register_addr_space (const char *str, addr_space_t as);
extern enum machine_mode default_addr_space_pointer_mode (addr_space_t);
extern enum machine_mode default_addr_space_address_mode (addr_space_t);
extern bool default_addr_space_valid_pointer_mode(enum machine_mode mode, addr_space_t as);
extern bool default_addr_space_legitimate_address_p(enum machine_mode mode, rtx mem, bool strict, addr_space_t as);
extern rtx default_addr_space_legitimize_address(rtx x, rtx oldx, enum machine_mode mode, addr_space_t as);

__visible int plugin_is_GPL_compatible;

static struct plugin_info checker_plugin_info = {
	.version	= "201602181345",
	.help		= "user\tturn on user/kernel address space checking\n"
			  "context\tturn on locking context checking\n"
};

#define ADDR_SPACE_KERNEL		0
#define ADDR_SPACE_FORCE_KERNEL		1
#define ADDR_SPACE_USER			2
#define ADDR_SPACE_FORCE_USER		3
#define ADDR_SPACE_IOMEM		0
#define ADDR_SPACE_FORCE_IOMEM		0
#define ADDR_SPACE_PERCPU		0
#define ADDR_SPACE_FORCE_PERCPU		0
#define ADDR_SPACE_RCU			0
#define ADDR_SPACE_FORCE_RCU		0

static enum machine_mode checker_addr_space_pointer_mode(addr_space_t addrspace)
{
	return default_addr_space_pointer_mode(ADDR_SPACE_GENERIC);
}

static enum machine_mode checker_addr_space_address_mode(addr_space_t addrspace)
{
	return default_addr_space_address_mode(ADDR_SPACE_GENERIC);
}

static bool checker_addr_space_valid_pointer_mode(enum machine_mode mode, addr_space_t as)
{
	return default_addr_space_valid_pointer_mode(mode, as);
}

static bool checker_addr_space_legitimate_address_p(enum machine_mode mode, rtx mem, bool strict, addr_space_t as)
{
	return default_addr_space_legitimate_address_p(mode, mem, strict, ADDR_SPACE_GENERIC);
}

static rtx checker_addr_space_legitimize_address(rtx x, rtx oldx, enum machine_mode mode, addr_space_t as)
{
	return default_addr_space_legitimize_address(x, oldx, mode, as);
}

static bool checker_addr_space_subset_p(addr_space_t subset, addr_space_t superset)
{
	if (subset == ADDR_SPACE_FORCE_KERNEL && superset == ADDR_SPACE_KERNEL)
		return true;

	if (subset == ADDR_SPACE_FORCE_USER && superset == ADDR_SPACE_USER)
		return true;

	if (subset == ADDR_SPACE_FORCE_IOMEM && superset == ADDR_SPACE_IOMEM)
		return true;

	if (subset == ADDR_SPACE_KERNEL && superset == ADDR_SPACE_FORCE_USER)
		return true;

	if (subset == ADDR_SPACE_KERNEL && superset == ADDR_SPACE_FORCE_IOMEM)
		return true;

	if (subset == ADDR_SPACE_USER && superset == ADDR_SPACE_FORCE_KERNEL)
		return true;

	if (subset == ADDR_SPACE_IOMEM && superset == ADDR_SPACE_FORCE_KERNEL)
		return true;

	return subset == superset;
}

static rtx checker_addr_space_convert(rtx op, tree from_type, tree to_type)
{
//	addr_space_t from_as = TYPE_ADDR_SPACE(TREE_TYPE(from_type));
//	addr_space_t to_as = TYPE_ADDR_SPACE(TREE_TYPE(to_type));

	return op;
}

static void register_checker_address_spaces(void *event_data, void *data)
{
	c_register_addr_space("__kernel", ADDR_SPACE_KERNEL);
	c_register_addr_space("__force_kernel", ADDR_SPACE_FORCE_KERNEL);
	c_register_addr_space("__user", ADDR_SPACE_USER);
	c_register_addr_space("__force_user", ADDR_SPACE_FORCE_USER);
//	c_register_addr_space("__iomem", ADDR_SPACE_IOMEM);
//	c_register_addr_space("__force_iomem", ADDR_SPACE_FORCE_IOMEM);
//	c_register_addr_space("__percpu", ADDR_SPACE_PERCPU);
//	c_register_addr_space("__force_percpu", ADDR_SPACE_FORCE_PERCPU);
//	c_register_addr_space("__rcu", ADDR_SPACE_RCU);
//	c_register_addr_space("__force_rcu", ADDR_SPACE_FORCE_RCU);

	targetm.addr_space.pointer_mode		= checker_addr_space_pointer_mode;
	targetm.addr_space.address_mode		= checker_addr_space_address_mode;
	targetm.addr_space.valid_pointer_mode	= checker_addr_space_valid_pointer_mode;
	targetm.addr_space.legitimate_address_p	= checker_addr_space_legitimate_address_p;
//	targetm.addr_space.legitimize_address	= checker_addr_space_legitimize_address;
	targetm.addr_space.subset_p		= checker_addr_space_subset_p;
	targetm.addr_space.convert		= checker_addr_space_convert;
}

static bool split_context_attribute(tree args, tree *lock, tree *in, tree *out)
{
	*in = TREE_VALUE(args);

	if (TREE_CODE(*in) != INTEGER_CST) {
		*lock = *in;
		args = TREE_CHAIN(args);
		*in = TREE_VALUE(args);
	} else
		*lock = NULL_TREE;

	args = TREE_CHAIN(args);
	if (*lock && !args)
		return false;

	*out = TREE_VALUE(args);
	return true;
}

static tree handle_context_attribute(tree *node, tree name, tree args, int flags, bool *no_add_attrs)
{
	*no_add_attrs = true;
	tree lock, in, out;

	if (TREE_CODE(*node) != FUNCTION_DECL) {
		error("%qE attribute applies to functions only (%qD)", name, *node);
		return NULL_TREE;
	}

	if (!split_context_attribute(args, &lock, &in, &out)) {
		error("%qE attribute needs two integers after the lock expression", name);
		return NULL_TREE;
	}

	if (TREE_CODE(in) != INTEGER_CST) {
		error("the 'in' argument of the %qE attribute must be an integer (%qE)", name, in);
		return NULL_TREE;
	}

	if (TREE_CODE(out) != INTEGER_CST) {
		error("the 'out' argument of the %qE attribute must be an integer (%qE)", name, out);
		return NULL_TREE;
	}

	*no_add_attrs = false;
	return NULL_TREE;
}

static struct attribute_spec context_attr = {
	.name			= "context",
	.min_length		= 2,
	.max_length		= 3,
	.decl_required		= true,
	.type_required		= false,
	.function_type_required	= false,
	.handler		= handle_context_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity	= true
#endif
};

static void register_attributes(void *event_data, void *data)
{
	register_attribute(&context_attr);
}

static const char context_function[] = "__context__";
static GTY(()) tree context_function_decl;

static const char context_error[] = "__context_error__";
static GTY(()) tree context_error_decl;

static void context_start_unit(void __unused *gcc_data, void __unused *user_data)
{
	tree fntype, attr;

	// void __context__(void *, int);
	fntype = build_function_type_list(void_type_node, ptr_type_node, integer_type_node, NULL_TREE);
	context_function_decl = build_fn_decl(context_function, fntype);

	TREE_PUBLIC(context_function_decl) = 1;
	TREE_USED(context_function_decl) = 1;
	DECL_EXTERNAL(context_function_decl) = 1;
	DECL_ARTIFICIAL(context_function_decl) = 1;
	DECL_PRESERVE_P(context_function_decl) = 1;
//	TREE_NOTHROW(context_function_decl) = 1;
//	DECL_UNINLINABLE(context_function_decl) = 1;
	DECL_ASSEMBLER_NAME(context_function_decl); // for LTO
	lang_hooks.decls.pushdecl(context_function_decl);

	// void __context_error__(const void *, int) __attribute__((error("context error")));
	fntype = build_function_type_list(void_type_node, const_ptr_type_node, integer_type_node, NULL_TREE);
	context_error_decl = build_fn_decl(context_error, fntype);

	TREE_PUBLIC(context_error_decl) = 1;
	TREE_USED(context_error_decl) = 1;
	DECL_EXTERNAL(context_error_decl) = 1;
	DECL_ARTIFICIAL(context_error_decl) = 1;
	DECL_PRESERVE_P(context_error_decl) = 1;
//	TREE_NOTHROW(context_error_decl) = 1;
//	DECL_UNINLINABLE(context_error_decl) = 1;
	TREE_THIS_VOLATILE(context_error_decl) = 1;
	DECL_ASSEMBLER_NAME(context_error_decl);

	attr = tree_cons(NULL, build_const_char_string(14, "context error"), NULL);
	attr = tree_cons(get_identifier("error"), attr, NULL);
	decl_attributes(&context_error_decl, attr, 0);
}

static bool context_gate(void)
{
	tree context_attr;

return true;

	context_attr = lookup_attribute("context", DECL_ATTRIBUTES(current_function_decl));
	return context_attr != NULL_TREE;
}

static basic_block verify_context_before(gimple_stmt_iterator *gsi, tree context, tree inout, tree error)
{
	gimple stmt;
	basic_block cond_bb, join_bb, true_bb;
	edge e;
	location_t loc;
	const char *file;
	int line;
	size_t len;
	tree filename;

	stmt = gsi_stmt(*gsi);
	if (gimple_has_location(stmt)) {
		loc = gimple_location(stmt);
		file = gimple_filename(stmt);
		line = gimple_lineno(stmt);
	} else {
		loc = DECL_SOURCE_LOCATION(current_function_decl);
		file = DECL_SOURCE_FILE(current_function_decl);
		line = DECL_SOURCE_LINE(current_function_decl);
	}
	gcc_assert(file);

	// if (context != count) __context_error__(__FILE__, __LINE__);
	stmt = gimple_build_cond(NE_EXPR, context, inout, NULL_TREE, NULL_TREE);
	gimple_set_location(stmt, loc);
	gsi_insert_before(gsi, stmt, GSI_NEW_STMT);

	cond_bb = gsi_bb(*gsi);
	gcc_assert(!gsi_end_p(*gsi));
	gcc_assert(stmt == gsi_stmt(*gsi));

	e = split_block(cond_bb, gsi_stmt(*gsi));
	cond_bb = e->src;
	join_bb = e->dest;
	e->flags = EDGE_FALSE_VALUE;
	e->probability = REG_BR_PROB_BASE;

	true_bb = create_empty_bb(EXIT_BLOCK_PTR_FOR_FN(cfun)->prev_bb);
	make_edge(cond_bb, true_bb, EDGE_TRUE_VALUE);
	make_edge(true_bb, join_bb, EDGE_FALLTHRU);

	set_immediate_dominator(CDI_DOMINATORS, true_bb, cond_bb);
	set_immediate_dominator(CDI_DOMINATORS, join_bb, cond_bb);

	gcc_assert(cond_bb->loop_father == join_bb->loop_father);
	add_bb_to_loop(true_bb, cond_bb->loop_father);

	// insert call to builtin_trap or __context_error__
	*gsi = gsi_start_bb(true_bb);

//	stmt = gimple_build_call(builtin_decl_implicit(BUILT_IN_TRAP), 0);
	len = strlen(file) + 1;
	filename = build_const_char_string(len, file);
	filename = build1(ADDR_EXPR, const_ptr_type_node, filename);
	stmt = gimple_build_call(error, 2, filename, build_int_cst(NULL_TREE, line));
	gimple_set_location(stmt, loc);
	gsi_insert_after(gsi, stmt, GSI_CONTINUE_LINKING);

	*gsi = gsi_start_nondebug_bb(join_bb);
	return join_bb;
}

static void update_context(gimple_stmt_iterator *gsi, tree context, int diff)
{
	gimple assign;
	tree op;

	op = fold_build2_loc(UNKNOWN_LOCATION, PLUS_EXPR, integer_type_node, context, build_int_cst(integer_type_node, diff));
	assign = gimple_build_assign(context, op);
	gsi_insert_after(gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);
}

static basic_block track_context(basic_block bb, tree context)
{
	gimple_stmt_iterator gsi;
	gimple assign;

	// adjust context according to the context information on any call stmt
	for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
		gimple stmt = gsi_stmt(gsi);
		tree fndecl, context_attr;
		tree lock, in, out;
		int incount, outcount;

		if (!is_gimple_call(stmt))
			continue;

		fndecl = gimple_call_fndecl(stmt);
		if (!fndecl)
			continue;

		if (fndecl == context_function_decl) {
			unsigned int num_ops = gimple_num_ops(stmt);
			int diff = tree_to_shwi(gimple_op(stmt, num_ops - 1));

			gcc_assert(diff);
			update_context(&gsi, context, diff);
			continue;
		}

		context_attr = lookup_attribute("context", DECL_ATTRIBUTES(fndecl));
		if (!context_attr)
			continue;

		gcc_assert(split_context_attribute(TREE_VALUE(context_attr), &lock, &in, &out));
		incount = tree_to_shwi(in);
		outcount = tree_to_shwi(out);
		bb = verify_context_before(&gsi, context, in, context_error_decl);
		update_context(&gsi, context, outcount - incount);
	}

	return bb;
}

static bool bb_any_loop(basic_block bb)
{
	return bb_loop_depth(bb) || (bb->flags & BB_IRREDUCIBLE_LOOP);
}

static unsigned int context_execute(void)
{
	basic_block bb;
	gimple assign;
	gimple_stmt_iterator gsi;
	tree context_attr, context;
	tree lock, in, out;

	loop_optimizer_init(LOOPS_NORMAL | LOOPS_HAVE_RECORDED_EXITS);
	gcc_assert(current_loops);

	calculate_dominance_info(CDI_DOMINATORS);
	calculate_dominance_info(CDI_POST_DOMINATORS);

	context_attr = lookup_attribute("context", DECL_ATTRIBUTES(current_function_decl));
	if (context_attr) {
		gcc_assert(split_context_attribute(TREE_VALUE(context_attr), &lock, &in, &out));
	} else {
		in = out = integer_zero_node;
	}

	// 1. create local context variable
	context = create_tmp_var(integer_type_node, "context");
	add_referenced_var(context);
	mark_sym_for_renaming(context);

	// 2. initialize local context variable
	gcc_assert(single_succ_p(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
	bb = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
	if (!single_pred_p(bb)) {
		gcc_assert(bb_any_loop(bb));
		split_edge(single_succ_edge(ENTRY_BLOCK_PTR_FOR_FN(cfun)));
		bb = single_succ(ENTRY_BLOCK_PTR_FOR_FN(cfun));
	}
	gsi = gsi_start_bb(bb);
	assign = gimple_build_assign(context, in);
	gsi_insert_before(&gsi, assign, GSI_NEW_STMT);
	update_stmt(assign);

	// 3. instrument each BB to track the local context variable
	FOR_EACH_BB_FN(bb, cfun) {
		bb = track_context(bb, context);
	}

	// 4. verify the local context variable against the expected state
	if (EDGE_COUNT(EXIT_BLOCK_PTR_FOR_FN(cfun)->preds)) {
		gcc_assert(single_pred_p(EXIT_BLOCK_PTR_FOR_FN(cfun)));
		gsi = gsi_last_nondebug_bb(single_pred(EXIT_BLOCK_PTR_FOR_FN(cfun)));
		verify_context_before(&gsi, context, out, context_error_decl);
	}

	free_dominance_info(CDI_DOMINATORS);
	free_dominance_info(CDI_POST_DOMINATORS);
	loop_optimizer_finalize();
	return 0;
}

#define PASS_NAME context
#define PROPERTIES_REQUIRED PROP_gimple_leh | PROP_cfg
//#define TODO_FLAGS_START TODO_verify_ssa | TODO_verify_flow | TODO_verify_stmts
#define TODO_FLAGS_FINISH TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_verify_flow | TODO_update_ssa
#include "gcc-generate-gimple-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;
	bool enable_user, enable_context;

	static const struct ggc_root_tab gt_ggc_r_gt_checker[] = {
		{
			.base = &context_function_decl,
			.nelt = 1,
			.stride = sizeof(context_function_decl),
			.cb = &gt_ggc_mx_tree_node,
			.pchw = &gt_pch_nx_tree_node
		},
		{
			.base = &context_error_decl,
			.nelt = 1,
			.stride = sizeof(context_error_decl),
			.cb = &gt_ggc_mx_tree_node,
			.pchw = &gt_pch_nx_tree_node
		},
		LAST_GGC_ROOT_TAB
	};

//	PASS_INFO(context, "ssa", 1, PASS_POS_INSERT_AFTER);
	PASS_INFO(context, "phiprop", 1, PASS_POS_INSERT_AFTER);

	if (!plugin_default_version_check(version, &gcc_version)) {
		error_gcc_version(version);
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &checker_plugin_info);

	enable_user = false;
	enable_context = false;
	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "user")) {
			enable_user = true;
			continue;
		}
		if (!strcmp(argv[i].key, "context")) {
			enable_context = true;
			continue;
		}
		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	if (enable_user)
		register_callback(plugin_name, PLUGIN_PRAGMAS, register_checker_address_spaces, NULL);
	if (enable_context) {
		register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);
		register_callback(plugin_name, PLUGIN_START_UNIT, context_start_unit, NULL);
		register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS, NULL, (void *)&gt_ggc_r_gt_checker);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &context_pass_info);
	}

	return 0;
}
