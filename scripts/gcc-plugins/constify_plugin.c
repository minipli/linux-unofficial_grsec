/*
 * Copyright 2011 by Emese Revfy <re.emese@gmail.com>
 * Copyright 2011-2017 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2, or (at your option) v3
 *
 * This gcc plugin constifies all structures which contain only function pointers or are explicitly marked for constification.
 *
 * Homepage:
 * http://www.grsecurity.net/~ephox/const_plugin/
 *
 * Usage:
 * $ gcc -I`gcc -print-file-name=plugin`/include -fPIC -shared -O2 -o constify_plugin.so constify_plugin.c
 * $ gcc -fplugin=constify_plugin.so test.c -O2
 */

#include "gcc-common.h"

// unused C type flag in all versions 4.5-6
#define TYPE_CONSTIFY_VISITED(TYPE) TYPE_LANG_FLAG_4(TYPE)

__visible int plugin_is_GPL_compatible;

static bool enabled = true;

static struct plugin_info const_plugin_info = {
	.version	= "201607241840",
	.help		= "disable\tturn off constification\n",
};

static struct {
	const char *name;
	const char *asm_op;
} const_sections[] = {
	{".init.rodata",     "\t.section\t.init.rodata,\"a\""},
	{".ref.rodata",      "\t.section\t.ref.rodata,\"a\""},
	{".devinit.rodata",  "\t.section\t.devinit.rodata,\"a\""},
	{".devexit.rodata",  "\t.section\t.devexit.rodata,\"a\""},
	{".cpuinit.rodata",  "\t.section\t.cpuinit.rodata,\"a\""},
	{".cpuexit.rodata",  "\t.section\t.cpuexit.rodata,\"a\""},
	{".meminit.rodata",  "\t.section\t.meminit.rodata,\"a\""},
	{".memexit.rodata",  "\t.section\t.memexit.rodata,\"a\""},
	{".data..read_only", "\t.section\t.data..read_only,\"a\""},
};

typedef struct {
	bool has_fptr_field;
	bool has_writable_field;
	bool has_do_const_field;
	bool has_no_const_field;
} constify_info;

static const_tree get_field_type(const_tree field)
{
	return strip_array_types(TREE_TYPE(field));
}

static bool is_fptr(const_tree field)
{
	const_tree ptr = get_field_type(field);

	if (TREE_CODE(ptr) != POINTER_TYPE)
		return false;

	return TREE_CODE(TREE_TYPE(ptr)) == FUNCTION_TYPE;
}

/*
 * determine whether the given structure type meets the requirements for automatic constification,
 * including the constification attributes on nested structure types
 */
static void constifiable(const_tree node, constify_info *cinfo)
{
	const_tree field;

	gcc_assert(TREE_CODE(node) == RECORD_TYPE || TREE_CODE(node) == UNION_TYPE);

	// e.g., pointer to structure fields while still constructing the structure type
	if (TYPE_FIELDS(node) == NULL_TREE)
		return;

	for (field = TYPE_FIELDS(node); field; field = TREE_CHAIN(field)) {
		const_tree type = get_field_type(field);
		enum tree_code code = TREE_CODE(type);

		if (node == type)
			continue;

		if (is_fptr(field))
			cinfo->has_fptr_field = true;
		else if (code == RECORD_TYPE || code == UNION_TYPE) {
			if (lookup_attribute("do_const", TYPE_ATTRIBUTES(type)))
				cinfo->has_do_const_field = true;
			else if (lookup_attribute("no_const", TYPE_ATTRIBUTES(type)))
				cinfo->has_no_const_field = true;
			else
				constifiable(type, cinfo);
		} else if (!TREE_READONLY(field))
			cinfo->has_writable_field = true;
	}
}

static bool constified(const_tree node)
{
	constify_info cinfo = {
		.has_fptr_field = false,
		.has_writable_field = false,
		.has_do_const_field = false,
		.has_no_const_field = false
	};

	gcc_assert(TREE_CODE(node) == RECORD_TYPE || TREE_CODE(node) == UNION_TYPE);

	if (lookup_attribute("no_const", TYPE_ATTRIBUTES(node))) {
//		gcc_assert(!TYPE_READONLY(node));
		return false;
	}

	if (lookup_attribute("do_const", TYPE_ATTRIBUTES(node))) {
		gcc_assert(TYPE_READONLY(node));
		return true;
	}

	constifiable(node, &cinfo);
	if ((!cinfo.has_fptr_field || cinfo.has_writable_field || cinfo.has_no_const_field) && !cinfo.has_do_const_field)
		return false;

	return TYPE_READONLY(node);
}

static void deconstify_tree(tree node);

static void deconstify_type(tree type)
{
	tree field;

	gcc_assert(TREE_CODE(type) == RECORD_TYPE || TREE_CODE(type) == UNION_TYPE);

	for (field = TYPE_FIELDS(type); field; field = TREE_CHAIN(field)) {
		const_tree fieldtype = get_field_type(field);

		// special case handling of simple ptr-to-same-array-type members
		if (TREE_CODE(TREE_TYPE(field)) == POINTER_TYPE) {
			tree ptrtype = TREE_TYPE(TREE_TYPE(field));

			if (TREE_TYPE(TREE_TYPE(field)) == type)
				continue;
			if (TREE_CODE(ptrtype) != RECORD_TYPE && TREE_CODE(ptrtype) != UNION_TYPE)
				continue;
			if (!constified(ptrtype))
				continue;
			if (TYPE_MAIN_VARIANT(ptrtype) == TYPE_MAIN_VARIANT(type))
				TREE_TYPE(field) = build_pointer_type(build_qualified_type(type, TYPE_QUALS(ptrtype) & ~TYPE_QUAL_CONST));
			continue;
		}
		if (TREE_CODE(fieldtype) != RECORD_TYPE && TREE_CODE(fieldtype) != UNION_TYPE)
			continue;
		if (!constified(fieldtype))
			continue;

		deconstify_tree(field);
		TREE_READONLY(field) = 0;
	}
	TYPE_READONLY(type) = 0;
	C_TYPE_FIELDS_READONLY(type) = 0;
	if (lookup_attribute("do_const", TYPE_ATTRIBUTES(type))) {
		TYPE_ATTRIBUTES(type) = copy_list(TYPE_ATTRIBUTES(type));
		TYPE_ATTRIBUTES(type) = remove_attribute("do_const", TYPE_ATTRIBUTES(type));
	}
}

static void deconstify_tree(tree node)
{
	tree old_type, new_type, field;

	old_type = TREE_TYPE(node);
	while (TREE_CODE(old_type) == ARRAY_TYPE && TREE_CODE(TREE_TYPE(old_type)) != ARRAY_TYPE) {
		node = TREE_TYPE(node) = copy_node(old_type);
		old_type = TREE_TYPE(old_type);
	}

	gcc_assert(TREE_CODE(old_type) == RECORD_TYPE || TREE_CODE(old_type) == UNION_TYPE);
	gcc_assert(TYPE_READONLY(old_type) && (TYPE_QUALS(old_type) & TYPE_QUAL_CONST));

	new_type = build_qualified_type(old_type, TYPE_QUALS(old_type) & ~TYPE_QUAL_CONST);
	TYPE_FIELDS(new_type) = copy_list(TYPE_FIELDS(new_type));
	for (field = TYPE_FIELDS(new_type); field; field = TREE_CHAIN(field))
		DECL_FIELD_CONTEXT(field) = new_type;

	deconstify_type(new_type);

	TREE_TYPE(node) = new_type;
}

static tree handle_no_const_attribute(tree *node, tree name, tree args __unused, int flags __unused, bool *no_add_attrs)
{
	tree type;
	constify_info cinfo = {
		.has_fptr_field = false,
		.has_writable_field = false,
		.has_do_const_field = false,
		.has_no_const_field = false
	};

	*no_add_attrs = true;
	if (TREE_CODE(*node) == FUNCTION_DECL) {
		error("%qE attribute does not apply to functions (%qF)", name, *node);
		return NULL_TREE;
	}

	if (TREE_CODE(*node) == PARM_DECL) {
		error("%qE attribute does not apply to function parameters (%qD)", name, *node);
		return NULL_TREE;
	}

	if (TREE_CODE(*node) == VAR_DECL) {
		error("%qE attribute does not apply to variables (%qD)", name, *node);
		return NULL_TREE;
	}

	if (TYPE_P(*node)) {
		type = *node;
	} else {
		if (TREE_CODE(*node) != TYPE_DECL) {
			error("%qE attribute does not apply to %qD (%qT)", name, *node, TREE_TYPE(*node));
			return NULL_TREE;
		}
		type = TREE_TYPE(*node);
	}

	if (TREE_CODE(type) != RECORD_TYPE && TREE_CODE(type) != UNION_TYPE) {
		error("%qE attribute used on %qT applies to struct and union types only", name, type);
		return NULL_TREE;
	}

	if (lookup_attribute(IDENTIFIER_POINTER(name), TYPE_ATTRIBUTES(type))) {
		error("%qE attribute is already applied to the type %qT", name, type);
		return NULL_TREE;
	}

	if (TYPE_P(*node)) {
		if (lookup_attribute("do_const", TYPE_ATTRIBUTES(type)))
			error("%qE attribute used on type %qT is incompatible with 'do_const'", name, type);
		else
			*no_add_attrs = false;
		return NULL_TREE;
	}

	constifiable(type, &cinfo);
	if ((cinfo.has_fptr_field && !cinfo.has_writable_field && !cinfo.has_no_const_field) || lookup_attribute("do_const", TYPE_ATTRIBUTES(type))) {
		if (enabled) {
			if TYPE_P(*node)
				deconstify_type(*node);
			else
				deconstify_tree(*node);
		}
		if (TYPE_P(*node))
			TYPE_CONSTIFY_VISITED(*node) = 1;
		else
			TYPE_CONSTIFY_VISITED(TREE_TYPE(*node)) = 1;
		return NULL_TREE;
	}

	if (enabled && TYPE_FIELDS(type))
		error("%qE attribute used on type %qT that is not constified", name, type);
	return NULL_TREE;
}

static void constify_type(tree type)
{
	gcc_assert(type == TYPE_MAIN_VARIANT(type));
	TYPE_READONLY(type) = 1;
	C_TYPE_FIELDS_READONLY(type) = 1;
	TYPE_CONSTIFY_VISITED(type) = 1;
}

static tree handle_do_const_attribute(tree *node, tree name, tree args __unused, int flags __unused, bool *no_add_attrs)
{
	*no_add_attrs = true;
	if (!TYPE_P(*node)) {
		error("%qE attribute applies to types only (%qD)", name, *node);
		return NULL_TREE;
	}

	if (TREE_CODE(*node) != RECORD_TYPE && TREE_CODE(*node) != UNION_TYPE) {
		error("%qE attribute used on %qT applies to struct and union types only", name, *node);
		return NULL_TREE;
	}

	if (lookup_attribute(IDENTIFIER_POINTER(name), TYPE_ATTRIBUTES(*node))) {
		error("%qE attribute used on %qT is already applied to the type", name, *node);
		return NULL_TREE;
	}

	if (lookup_attribute("no_const", TYPE_ATTRIBUTES(*node))) {
		error("%qE attribute used on %qT is incompatible with 'no_const'", name, *node);
		return NULL_TREE;
	}

	*no_add_attrs = false;
	return NULL_TREE;
}

static struct attribute_spec no_const_attr = {
	.name			= "no_const",
	.min_length		= 0,
	.max_length		= 0,
	.decl_required		= false,
	.type_required		= false,
	.function_type_required	= false,
	.handler		= handle_no_const_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity	= true
#endif
};

static struct attribute_spec do_const_attr = {
	.name			= "do_const",
	.min_length		= 0,
	.max_length		= 0,
	.decl_required		= false,
	.type_required		= false,
	.function_type_required	= false,
	.handler		= handle_do_const_attribute,
#if BUILDING_GCC_VERSION >= 4007
	.affects_type_identity	= true
#endif
};

static void register_attributes(void *event_data, void *data)
{
	register_attribute(&no_const_attr);
	register_attribute(&do_const_attr);
}

static void finish_type(void *event_data, void *data __unused)
{
	tree type = (tree)event_data;
	constify_info cinfo = {
		.has_fptr_field = false,
		.has_writable_field = false,
		.has_do_const_field = false,
		.has_no_const_field = false
	};

	if (type == NULL_TREE || type == error_mark_node)
		return;

#if BUILDING_GCC_VERSION >= 5000
	if (TREE_CODE(type) == ENUMERAL_TYPE)
		return;
#endif

	if (TYPE_FIELDS(type) == NULL_TREE || TYPE_CONSTIFY_VISITED(type))
		return;

	constifiable(type, &cinfo);

	if (lookup_attribute("no_const", TYPE_ATTRIBUTES(type))) {
		if ((cinfo.has_fptr_field && !cinfo.has_writable_field && !cinfo.has_no_const_field) || cinfo.has_do_const_field) {
			deconstify_type(type);
			TYPE_CONSTIFY_VISITED(type) = 1;
		} else
			error("'no_const' attribute used on type %qT that is not constified", type);
		return;
	}

	if (lookup_attribute("do_const", TYPE_ATTRIBUTES(type))) {
		if (!cinfo.has_writable_field && !cinfo.has_no_const_field) {
			error("'do_const' attribute used on type %qT that is%sconstified", type, cinfo.has_fptr_field ? " " : " not ");
			return;
		}
		constify_type(type);
		return;
	}

	if (cinfo.has_fptr_field && !cinfo.has_writable_field && !cinfo.has_no_const_field) {
		if (lookup_attribute("do_const", TYPE_ATTRIBUTES(type))) {
			error("'do_const' attribute used on type %qT that is constified", type);
			return;
		}
		constify_type(type);
//		TYPE_ATTRIBUTES(type) = copy_list(TYPE_ATTRIBUTES(type));
//		TYPE_ATTRIBUTES(type) = tree_cons(get_identifier("do_const"), NULL_TREE, TYPE_ATTRIBUTES(type));
		return;
	}

	deconstify_type(type);
	TYPE_CONSTIFY_VISITED(type) = 1;
}

static bool is_constified_var(varpool_node_ptr node)
{
	tree var = NODE_DECL(node);
	tree type = TREE_TYPE(var);

	if (node->alias)
		return false;

	if (DECL_EXTERNAL(var))
		return false;

	// XXX handle more complex nesting of arrays/structs
	if (TREE_CODE(type) == ARRAY_TYPE)
		type = TREE_TYPE(type);

	if (TREE_CODE(type) != RECORD_TYPE && TREE_CODE(type) != UNION_TYPE)
		return false;

	if (!TYPE_READONLY(type) || !C_TYPE_FIELDS_READONLY(type))
		return false;

	if (!TYPE_CONSTIFY_VISITED(type))
		return false;

	return true;
}

static void check_section_mismatch(varpool_node_ptr node)
{
	tree var, section;
	size_t i;
	const char *name;

	var = NODE_DECL(node);
	name = get_decl_section_name(var);
	section = lookup_attribute("section", DECL_ATTRIBUTES(var));
	if (!section) {
		if (name) {
			fprintf(stderr, "DECL_SECTION [%s] ", name);
			dump_varpool_node(stderr, node);
			gcc_unreachable();
		}
		return;
	} else
		gcc_assert(name);

//fprintf(stderr, "SECTIONAME: [%s] ", get_decl_section_name(var));
//debug_tree(var);

	gcc_assert(!TREE_CHAIN(section));
	gcc_assert(TREE_VALUE(section));

	section = TREE_VALUE(TREE_VALUE(section));
	gcc_assert(!strcmp(TREE_STRING_POINTER(section), name));
//debug_tree(section);

	for (i = 0; i < ARRAY_SIZE(const_sections); i++)
		if (!strcmp(const_sections[i].name, name))
			return;

	error_at(DECL_SOURCE_LOCATION(var), "constified variable %qD placed into writable section %E", var, section);
}

// this works around a gcc bug/feature where uninitialized globals
// are moved into the .bss section regardless of any constification
// see gcc/varasm.c:bss_initializer_p()
static void fix_initializer(varpool_node_ptr node)
{
	tree var = NODE_DECL(node);
	tree type = TREE_TYPE(var);

	if (DECL_INITIAL(var))
		return;

	DECL_INITIAL(var) = build_constructor(type, NULL);
//	inform(DECL_SOURCE_LOCATION(var), "constified variable %qE moved into .rodata", var);
}

static void check_global_variables(void *event_data __unused, void *data __unused)
{
	varpool_node_ptr node;

	FOR_EACH_VARIABLE(node) {
		if (!is_constified_var(node))
			continue;

		check_section_mismatch(node);
		fix_initializer(node);
	}
}

static unsigned int check_local_variables_execute(void)
{
	unsigned int ret = 0;
	tree var;

	unsigned int i;

	FOR_EACH_LOCAL_DECL(cfun, i, var) {
		tree type = TREE_TYPE(var);

		gcc_assert(DECL_P(var));
		if (is_global_var(var))
			continue;

		if (TREE_CODE(type) != RECORD_TYPE && TREE_CODE(type) != UNION_TYPE)
			continue;

		if (!TYPE_READONLY(type) || !C_TYPE_FIELDS_READONLY(type))
			continue;

		if (!TYPE_CONSTIFY_VISITED(type))
			continue;

		error_at(DECL_SOURCE_LOCATION(var), "constified variable %qE cannot be local", var);
		ret = 1;
	}
	return ret;
}

#define PASS_NAME check_local_variables
#define NO_GATE
#include "gcc-generate-gimple-pass.h"

static unsigned int (*old_section_type_flags)(tree decl, const char *name, int reloc);

static unsigned int constify_section_type_flags(tree decl, const char *name, int reloc)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(const_sections); i++)
		if (!strcmp(const_sections[i].name, name))
			return 0;

	return old_section_type_flags(decl, name, reloc);
}

static void constify_start_unit(void *gcc_data __unused, void *user_data __unused)
{
//	size_t i;

//	for (i = 0; i < ARRAY_SIZE(const_sections); i++)
//		const_sections[i].section = get_unnamed_section(0, output_section_asm_op, const_sections[i].asm_op);
//		const_sections[i].section = get_section(const_sections[i].name, 0, NULL);

	old_section_type_flags = targetm.section_type_flags;
	targetm.section_type_flags = constify_section_type_flags;
}

__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;

	PASS_INFO(check_local_variables, "ssa", 1, PASS_POS_INSERT_BEFORE);

	if (!plugin_default_version_check(version, &gcc_version)) {
		error_gcc_version(version);
		return 1;
	}

	for (i = 0; i < argc; ++i) {
		if (!(strcmp(argv[i].key, "disable"))) {
			enabled = false;
			continue;
		}
		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}

	if (strncmp(lang_hooks.name, "GNU C", 5) && !strncmp(lang_hooks.name, "GNU C+", 6)) {
		inform(UNKNOWN_LOCATION, G_("%s supports C only, not %s"), plugin_name, lang_hooks.name);
		enabled = false;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &const_plugin_info);
	if (enabled) {
		register_callback(plugin_name, PLUGIN_ALL_IPA_PASSES_START, check_global_variables, NULL);
		register_callback(plugin_name, PLUGIN_FINISH_TYPE, finish_type, NULL);
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &check_local_variables_pass_info);
		register_callback(plugin_name, PLUGIN_START_UNIT, constify_start_unit, NULL);
	}
	register_callback(plugin_name, PLUGIN_ATTRIBUTES, register_attributes, NULL);

	return 0;
}
