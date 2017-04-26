/*
 * Copyright 2011-2017 by the PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to find the distribution of k*alloc sizes
 *
 * TODO:
 *
 * BUGS:
 * - none known
 */

#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

static struct plugin_info kallocstat_plugin_info = {
	.version	= "201602181345",
	.help		= NULL
};

static const char * const kalloc_functions[] = {
	"__kmalloc",
	"kmalloc",
	"kmalloc_large",
	"kmalloc_node",
	"kmalloc_order",
	"kmalloc_order_trace",
	"kmalloc_slab",
	"kzalloc",
	"kzalloc_node",
};

static bool is_kalloc(const char *fnname)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(kalloc_functions); i++)
		if (!strcmp(fnname, kalloc_functions[i]))
			return true;
	return false;
}

static unsigned int kallocstat_execute(void)
{
	basic_block bb;

	// 1. loop through BBs and GIMPLE statements
	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;
		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			// gimple match: 
			tree fndecl, size;
			gimple stmt;
			const char *fnname;

			// is it a call
			stmt = gsi_stmt(gsi);
			if (!is_gimple_call(stmt))
				continue;
			fndecl = gimple_call_fndecl(stmt);
			if (fndecl == NULL_TREE)
				continue;
			if (TREE_CODE(fndecl) != FUNCTION_DECL)
				continue;

			// is it a call to k*alloc
			fnname = DECL_NAME_POINTER(fndecl);
			if (!is_kalloc(fnname))
				continue;

			// is the size arg const or the result of a simple const assignment
			size = gimple_call_arg(stmt, 0);
			while (true) {
				expanded_location xloc;
				size_t size_val;

				if (TREE_CONSTANT(size)) {
					xloc = expand_location(gimple_location(stmt));
					if (!xloc.file)
						xloc = expand_location(DECL_SOURCE_LOCATION(current_function_decl));
					size_val = TREE_INT_CST_LOW(size);
					fprintf(stderr, "kallocsize: %8zu %8zx %s %s:%u\n", size_val, size_val, fnname, xloc.file, xloc.line);
					break;
				}

				if (TREE_CODE(size) != SSA_NAME)
					break;
				stmt = SSA_NAME_DEF_STMT(size);
//debug_gimple_stmt(stmt);
//debug_tree(size);
				if (!stmt || !is_gimple_assign(stmt))
					break;
				if (gimple_num_ops(stmt) != 2)
					break;
				size = gimple_assign_rhs1(stmt);
			}
//print_gimple_stmt(stderr, call_stmt, 0, TDF_LINENO);
//debug_tree(gimple_call_fn(call_stmt));
//print_node(stderr, "pax", fndecl, 4);
		}
	}

	return 0;
}

#define PASS_NAME kallocstat
#define NO_GATE
#include "gcc-generate-gimple-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;

	PASS_INFO(kallocstat, "ssa", 1, PASS_POS_INSERT_AFTER);

	if (!plugin_default_version_check(version, &gcc_version)) {
		error_gcc_version(version);
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &kallocstat_plugin_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kallocstat_pass_info);

	return 0;
}
