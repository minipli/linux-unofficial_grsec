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

__visible int plugin_is_GPL_compatible;

tree report_size_overflow_decl;

tree size_overflow_type_HI;
tree size_overflow_type_SI;
tree size_overflow_type_DI;
tree size_overflow_type_TI;

bool check_fields, check_fns, check_fnptrs, check_vars;

static struct plugin_info size_overflow_plugin_info = {
	.version	= "20170102",
	.help		= "no-size-overflow\tturn off size overflow checking\n",
};

static tree handle_size_overflow_attribute(tree *node, tree __unused name, tree args, int __unused flags, bool *no_add_attrs)
{
	unsigned int arg_count;
	enum tree_code code = TREE_CODE(*node);

	switch (code) {
	case FUNCTION_DECL:
		arg_count = type_num_arguments(TREE_TYPE(*node));
		break;
	case FUNCTION_TYPE:
	case METHOD_TYPE:
		arg_count = type_num_arguments(*node);
		break;
	default:
		*no_add_attrs = true;
		debug_tree(*node);
		error("%s: %qE attribute only applies to functions", __func__, name);
		return NULL_TREE;
	}

	for (; args; args = TREE_CHAIN(args)) {
		int cur_val;
		tree position = TREE_VALUE(args);

		if (TREE_CODE(position) != INTEGER_CST) {
			error("%s: parameter isn't an integer", __func__);
			debug_tree(args);
			*no_add_attrs = true;
			return NULL_TREE;
		}

		cur_val = tree_to_shwi(position);
		if (cur_val < 0 || arg_count < (unsigned int)cur_val) {
			error("%s: parameter %d is outside range.", __func__, cur_val);
			*no_add_attrs = true;
			return NULL_TREE;
		}
	}
	return NULL_TREE;
}

static tree handle_intentional_overflow_attribute(tree *node, tree __unused name, tree args, int __unused flags, bool *no_add_attrs)
{
	unsigned int arg_count;
	HOST_WIDE_INT s_first_arg;
	enum tree_code code = TREE_CODE(*node);

	switch (code) {
	case FUNCTION_DECL:
		arg_count = type_num_arguments(TREE_TYPE(*node));
		break;
	case FUNCTION_TYPE:
	case METHOD_TYPE:
		arg_count = type_num_arguments(*node);
		break;
	case VAR_DECL:
	case FIELD_DECL:
		return NULL_TREE;
	default:
		*no_add_attrs = true;
		debug_tree(*node);
		error("%qE attribute only applies to functions, fields or vars", name);
		return NULL_TREE;
	}

	s_first_arg = tree_to_shwi(TREE_VALUE(args));
	if (s_first_arg == -1)
		return NULL_TREE;
	if (s_first_arg < -1)
		error("%s: parameter %d is outside range.", __func__, (int)s_first_arg);

	for (; args; args = TREE_CHAIN(args)) {
		unsigned int cur_val;

		if (TREE_CODE(TREE_VALUE(args)) != INTEGER_CST) {
			error("%s: parameter isn't an integer", __func__);
			debug_tree(args);
			*no_add_attrs = true;
			return NULL_TREE;
		}

		cur_val = (unsigned int)tree_to_uhwi(TREE_VALUE(args));
		if (cur_val > arg_count ) {
			error("%s: parameter %u is outside range. (arg_count: %u)", __func__, cur_val, arg_count);
			*no_add_attrs = true;
			return NULL_TREE;
		}
	}
	return NULL_TREE;
}

static struct attribute_spec size_overflow_attr = {
	.name				= "size_overflow",
	.min_length			= 1,
	.max_length			= -1,
	.decl_required			= true,
	.type_required			= false,
	.function_type_required		= false,
	.handler			= handle_size_overflow_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity		= false
#endif
};

static struct attribute_spec intentional_overflow_attr = {
	.name				= "intentional_overflow",
	.min_length			= 1,
	.max_length			= -1,
	.decl_required			= true,
	.type_required			= false,
	.function_type_required		= false,
	.handler			= handle_intentional_overflow_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity		= false
#endif
};

static void register_attributes(void __unused *event_data, void __unused *data)
{
	register_attribute(&size_overflow_attr);
	register_attribute(&intentional_overflow_attr);
}

static tree create_typedef(tree type, const char* ident)
{
	tree new_type, decl;

	new_type = build_variant_type_copy(type);
	decl = build_decl(BUILTINS_LOCATION, TYPE_DECL, get_identifier(ident), new_type);
	DECL_ORIGINAL_TYPE(decl) = type;
	TYPE_NAME(new_type) = decl;
	return new_type;
}

// Create the noreturn report_size_overflow() function decl.
static void size_overflow_start_unit(void __unused *gcc_data, void __unused *user_data)
{
	tree const_char_ptr_type_node;
	tree fntype;

	const_char_ptr_type_node = build_pointer_type(build_type_variant(char_type_node, 1, 0));

	size_overflow_type_HI = create_typedef(intHI_type_node, "size_overflow_type_HI");
	size_overflow_type_SI = create_typedef(intSI_type_node, "size_overflow_type_SI");
	size_overflow_type_DI = create_typedef(intDI_type_node, "size_overflow_type_DI");
	size_overflow_type_TI = create_typedef(intTI_type_node, "size_overflow_type_TI");

	// void report_size_overflow(const char *loc_file, unsigned int loc_line, const char *current_func, const char *ssa_var)
	fntype = build_function_type_list(void_type_node,
					  const_char_ptr_type_node,
					  unsigned_type_node,
					  const_char_ptr_type_node,
					  const_char_ptr_type_node,
					  NULL_TREE);
	report_size_overflow_decl = build_fn_decl("report_size_overflow", fntype);

	DECL_ASSEMBLER_NAME(report_size_overflow_decl);
	TREE_PUBLIC(report_size_overflow_decl) = 1;
	DECL_EXTERNAL(report_size_overflow_decl) = 1;
	DECL_ARTIFICIAL(report_size_overflow_decl) = 1;
//	TREE_THIS_VOLATILE(report_size_overflow_decl) = 1;
// !!!
	DECL_PRESERVE_P(report_size_overflow_decl) = 1;
	DECL_UNINLINABLE(report_size_overflow_decl) = 1;
	TREE_USED(report_size_overflow_decl) = 1;
	TREE_NOTHROW(report_size_overflow_decl) = 1;
}

static bool disable_ubsan_si_overflow_gate(void)
{
#if BUILDING_GCC_VERSION >= 4009
	flag_sanitize &= ~SANITIZE_SI_OVERFLOW;
#endif
	return true;
}

#define PASS_NAME disable_ubsan_si_overflow

#define NO_EXECUTE

#include "gcc-generate-gimple-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	int i;
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	bool enable = true;

	static const struct ggc_root_tab gt_ggc_r_gt_size_overflow[] = {
		{
			.base = &report_size_overflow_decl,
			.nelt = 1,
			.stride = sizeof(report_size_overflow_decl),
			.cb = &gt_ggc_mx_tree_node,
			.pchw = &gt_pch_nx_tree_node
		},
		LAST_GGC_ROOT_TAB
	};

	PASS_INFO(insert_size_overflow_asm, "ssa", 1, PASS_POS_INSERT_AFTER);
	PASS_INFO(size_overflow, "inline", 1, PASS_POS_INSERT_AFTER);
#if BUILDING_GCC_VERSION >= 4009
	PASS_INFO(disable_ubsan_si_overflow, "ubsan", 1, PASS_POS_REPLACE);
#endif

	if (!plugin_default_version_check(version, &gcc_version)) {
		error_gcc_version(version);
		return 1;
	}

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "no-size-overflow")) {
			enable = false;
			continue;
		}

		if (!strcmp(argv[i].key, "check-fields")) {
			check_fields = true;
			continue;
		}

		if (!strcmp(argv[i].key, "check-fns")) {
			check_fns = true;
			continue;
		}

		if (!strcmp(argv[i].key, "check-fptrs")) {
			check_fnptrs = true;
			continue;
		}

		if (!strcmp(argv[i].key, "check-vars")) {
			check_vars = true;
			continue;
		}

		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &size_overflow_plugin_info);
	if (enable) {
#if BUILDING_GCC_VERSION >= 4009
		if (flag_sanitize & SANITIZE_SI_OVERFLOW) {
			error(G_("ubsan SANITIZE_SI_OVERFLOW option is unsupported"));
			return 1;
		}
#endif
		register_callback(plugin_name, PLUGIN_START_UNIT, &size_overflow_start_unit, NULL);
		register_callback(plugin_name, PLUGIN_REGISTER_GGC_ROOTS, NULL, (void *)&gt_ggc_r_gt_size_overflow);
#if BUILDING_GCC_VERSION >= 4009
		flag_sanitize |= SANITIZE_SI_OVERFLOW;
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &disable_ubsan_si_overflow_pass_info);
#endif
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &insert_size_overflow_asm_pass_info);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &size_overflow_pass_info);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}
