/*
 * Copyright 2011-2017 by the PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Note: the choice of the license means that the compilation process is
 *       NOT 'eligible' as defined by gcc's library exception to the GPL v3,
 *       but for the kernel it doesn't matter since it doesn't link against
 *       any of the gcc libraries
 *
 * gcc plugin to make KERNEXEC/amd64 almost as good as it is on i386
 *
 * TODO:
 *
 * BUGS:
 * - none known
 */

#include "gcc-common.h"

__visible int plugin_is_GPL_compatible;

static struct plugin_info kernexec_plugin_info = {
	.version	= "201607271510",
	.help		= "method=[bts|or]\tinstrumentation method\n"
};

static void (*kernexec_instrument_fptr)(gimple_stmt_iterator *);
static void (*kernexec_instrument_retaddr)(rtx);

/*
 * add special KERNEXEC instrumentation: reload %r12 after it has been clobbered
 */
static void kernexec_reload_fptr_mask(gimple_stmt_iterator *gsi)
{
	gimple stmt;
	gasm *asm_movabs_stmt;

	// build asm volatile("movabs $0x8000000000000000, %%r12\n\t" : : : );
	stmt = gimple_build_asm_vec("movabs $0x8000000000000000, %%r12\n\t", NULL, NULL, NULL, NULL);
	asm_movabs_stmt = as_a_gasm(stmt);
	gimple_asm_set_volatile(asm_movabs_stmt, true);
	gsi_insert_after(gsi, asm_movabs_stmt, GSI_CONTINUE_LINKING);
	update_stmt(asm_movabs_stmt);
}

/*
 * find all asm() stmts that clobber r12 and add a reload of r12
 */
static unsigned int kernexec_reload_execute(void)
{
	basic_block bb;

	// 1. loop through BBs and GIMPLE statements
	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			// gimple match: __asm__ ("" :  :  : "r12");
			gimple stmt;
			gasm *asm_stmt;
			size_t nclobbers;

			// is it an asm ...
			stmt = gsi_stmt(gsi);
			if (gimple_code(stmt) != GIMPLE_ASM)
				continue;

			asm_stmt = as_a_gasm(stmt);

			// ... clobbering r12
			nclobbers = gimple_asm_nclobbers(asm_stmt);
			while (nclobbers--) {
				tree op = gimple_asm_clobber_op(asm_stmt, nclobbers);
				if (strcmp(TREE_STRING_POINTER(TREE_VALUE(op)), "r12"))
					continue;
				kernexec_reload_fptr_mask(&gsi);
//print_gimple_stmt(stderr, asm_stmt, 0, TDF_LINENO);
				break;
			}
		}
	}

	return 0;
}

/*
 * add special KERNEXEC instrumentation: force MSB of fptr to 1, which will produce
 * a non-canonical address from a userland ptr and will just trigger a GPF on dereference
 */
static void kernexec_instrument_fptr_bts(gimple_stmt_iterator *gsi)
{
	gimple assign_intptr, assign_new_fptr;
	gcall *call_stmt;
	tree intptr, orptr, old_fptr, new_fptr, kernexec_mask;

	call_stmt = as_a_gcall(gsi_stmt(*gsi));
	old_fptr = gimple_call_fn(call_stmt);

	// create temporary unsigned long variable used for bitops and cast fptr to it
	intptr = create_tmp_var(long_unsigned_type_node, "kernexec_bts");
	add_referenced_var(intptr);
	intptr = make_ssa_name(intptr, NULL);
	assign_intptr = gimple_build_assign(intptr, fold_convert(long_unsigned_type_node, old_fptr));
	SSA_NAME_DEF_STMT(intptr) = assign_intptr;
	gsi_insert_before(gsi, assign_intptr, GSI_SAME_STMT);
	update_stmt(assign_intptr);

	// apply logical or to temporary unsigned long and bitmask
	kernexec_mask = build_int_cstu(long_long_unsigned_type_node, 0x8000000000000000ULL);
//	kernexec_mask = build_int_cstu(long_long_unsigned_type_node, 0xffffffff80000000ULL);
	orptr = fold_build2(BIT_IOR_EXPR, long_long_unsigned_type_node, intptr, kernexec_mask);
	intptr = make_ssa_name(SSA_NAME_VAR(intptr), NULL);
	assign_intptr = gimple_build_assign(intptr, orptr);
	SSA_NAME_DEF_STMT(intptr) = assign_intptr;
	gsi_insert_before(gsi, assign_intptr, GSI_SAME_STMT);
	update_stmt(assign_intptr);

	// cast temporary unsigned long back to a temporary fptr variable
	new_fptr = create_tmp_var(TREE_TYPE(old_fptr), "kernexec_fptr");
	add_referenced_var(new_fptr);
	new_fptr = make_ssa_name(new_fptr, NULL);
	assign_new_fptr = gimple_build_assign(new_fptr, fold_convert(TREE_TYPE(old_fptr), intptr));
	SSA_NAME_DEF_STMT(new_fptr) = assign_new_fptr;
	gsi_insert_before(gsi, assign_new_fptr, GSI_SAME_STMT);
	update_stmt(assign_new_fptr);

	// replace call stmt fn with the new fptr
	gimple_call_set_fn(call_stmt, new_fptr);
	update_stmt(call_stmt);
}

static void kernexec_instrument_fptr_or(gimple_stmt_iterator *gsi)
{
	gimple stmt;
	gasm *asm_or_stmt;
	gcall *call_stmt;
	tree old_fptr, new_fptr, input, output;
#if BUILDING_GCC_VERSION <= 4007
	VEC(tree, gc) *inputs = NULL;
	VEC(tree, gc) *outputs = NULL;
#else
	vec<tree, va_gc> *inputs = NULL;
	vec<tree, va_gc> *outputs = NULL;
#endif

	call_stmt = as_a_gcall(gsi_stmt(*gsi));
	old_fptr = gimple_call_fn(call_stmt);

	// create temporary fptr variable
	new_fptr = create_tmp_var(TREE_TYPE(old_fptr), "kernexec_or");
	add_referenced_var(new_fptr);
	new_fptr = make_ssa_name(new_fptr, NULL);

	// build asm volatile("orq %%r12, %0\n\t" : "=r"(new_fptr) : "0"(old_fptr));
	input = build_tree_list(NULL_TREE, build_const_char_string(2, "0"));
	input = chainon(NULL_TREE, build_tree_list(input, old_fptr));
	output = build_tree_list(NULL_TREE, build_const_char_string(3, "=r"));
	output = chainon(NULL_TREE, build_tree_list(output, new_fptr));
#if BUILDING_GCC_VERSION <= 4007
	VEC_safe_push(tree, gc, inputs, input);
	VEC_safe_push(tree, gc, outputs, output);
#else
	vec_safe_push(inputs, input);
	vec_safe_push(outputs, output);
#endif
	stmt = gimple_build_asm_vec("orq %%r12, %0\n\t", inputs, outputs, NULL, NULL);
	asm_or_stmt = as_a_gasm(stmt);
	SSA_NAME_DEF_STMT(new_fptr) = asm_or_stmt;
	gimple_asm_set_volatile(asm_or_stmt, true);
	gsi_insert_before(gsi, asm_or_stmt, GSI_SAME_STMT);
	update_stmt(asm_or_stmt);

	// replace call stmt fn with the new fptr
	gimple_call_set_fn(call_stmt, new_fptr);
	update_stmt(call_stmt);
}

/*
 * find all C level function pointer dereferences and forcibly set the highest bit of the pointer
 */
static unsigned int kernexec_fptr_execute(void)
{
	basic_block bb;

	// 1. loop through BBs and GIMPLE statements
	FOR_EACH_BB_FN(bb, cfun) {
		gimple_stmt_iterator gsi;

		for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
			// gimple match: h_1 = get_fptr (); D.2709_3 = h_1 (x_2(D));
			tree fn;
			gimple stmt;
			gcall *call_stmt;

			// is it a call ...
			stmt = gsi_stmt(gsi);
			if (!is_gimple_call(stmt))
				continue;
			call_stmt = as_a_gcall(stmt);
			fn = gimple_call_fn(call_stmt);
			if (!fn)
				continue;
			if (TREE_CODE(fn) == ADDR_EXPR)
				continue;
			if (TREE_CODE(fn) == INTEGER_CST)
				continue;

			if (TREE_CODE(fn) != SSA_NAME) {
debug_tree(fn);
				gcc_unreachable();
			}

			// ... through a function pointer
			if (SSA_NAME_VAR(fn) != NULL_TREE) {
				fn = SSA_NAME_VAR(fn);
				if (TREE_CODE(fn) != VAR_DECL && TREE_CODE(fn) != PARM_DECL) {
					debug_tree(fn);
					gcc_unreachable();
				}
			}
			fn = TREE_TYPE(fn);
			if (TREE_CODE(fn) != POINTER_TYPE)
				continue;
			fn = TREE_TYPE(fn);
			if (TREE_CODE(fn) != FUNCTION_TYPE)
				continue;

			kernexec_instrument_fptr(&gsi);

//debug_tree(gimple_call_fn(call_stmt));
//print_gimple_stmt(stderr, call_stmt, 0, TDF_LINENO);
		}
	}

	return 0;
}

// add special KERNEXEC instrumentation: btsq $63,(%rsp) just before retn
static void kernexec_instrument_retaddr_bts(rtx insn)
{
	rtx btsq;
	rtvec argvec, constraintvec, labelvec;

	// create asm volatile("btsq $63,(%%rsp)":::)
	argvec = rtvec_alloc(0);
	constraintvec = rtvec_alloc(0);
	labelvec = rtvec_alloc(0);
	btsq = gen_rtx_ASM_OPERANDS(VOIDmode, "btsq $63,(%%rsp)", empty_string, 0, argvec, constraintvec, labelvec, RTL_LOCATION(insn));
	MEM_VOLATILE_P(btsq) = 1;
//	RTX_FRAME_RELATED_P(btsq) = 1; // not for ASM_OPERANDS
	emit_insn_before(btsq, insn);
}

// add special KERNEXEC instrumentation: orq %r12,(%rsp) just before retn
static void kernexec_instrument_retaddr_or(rtx insn)
{
	rtx orq;
	rtvec argvec, constraintvec, labelvec;

	// create asm volatile("orq %%r12,(%%rsp)":::)
	argvec = rtvec_alloc(0);
	constraintvec = rtvec_alloc(0);
	labelvec = rtvec_alloc(0);
	orq = gen_rtx_ASM_OPERANDS(VOIDmode, "orq %%r12,(%%rsp)", empty_string, 0, argvec, constraintvec, labelvec, RTL_LOCATION(insn));
	MEM_VOLATILE_P(orq) = 1;
//	RTX_FRAME_RELATED_P(orq) = 1; // not for ASM_OPERANDS
	emit_insn_before(orq, insn);
}

/*
 * find all asm level function returns and forcibly set the highest bit of the return address
 */
static unsigned int kernexec_retaddr_execute(void)
{
	rtx_insn *insn;

//	if (stack_realign_drap)
//		inform(DECL_SOURCE_LOCATION(current_function_decl), "drap detected in %s\n", IDENTIFIER_POINTER(DECL_NAME(current_function_decl)));

	// 1. find function returns
	for (insn = get_insns(); insn; insn = NEXT_INSN(insn)) {
		// rtl match: (jump_insn 41 40 42 2 (return) fptr.c:42 634 {return_internal} (nil))
		//            (jump_insn 12 9 11 2 (parallel [ (return) (unspec [ (0) ] UNSPEC_REP) ]) fptr.c:46 635 {return_internal_long} (nil))
		//            (jump_insn 97 96 98 6 (simple_return) fptr.c:50 -1 (nil) -> simple_return)
		rtx body;

		// is it a retn
		if (!JUMP_P(insn))
			continue;
		body = PATTERN(insn);
		if (GET_CODE(body) == PARALLEL)
			body = XVECEXP(body, 0, 0);
		if (!ANY_RETURN_P(body))
			continue;
		kernexec_instrument_retaddr(insn);
	}

//	print_simple_rtl(stderr, get_insns());
//	print_rtl(stderr, get_insns());

	return 0;
}

static bool kernexec_cmodel_check(void)
{
	tree section;

	if (ix86_cmodel != CM_KERNEL)
		return false;

	section = lookup_attribute("section", DECL_ATTRIBUTES(current_function_decl));
	if (!section || !TREE_VALUE(section))
		return true;

	section = TREE_VALUE(TREE_VALUE(section));
	if (strncmp(TREE_STRING_POINTER(section), ".vsyscall_", 10))
		return true;

	return false;
}

static bool kernexec_reload_gate(void)
{
	return kernexec_cmodel_check();
}

#define PASS_NAME kernexec_reload
#define TODO_FLAGS_FINISH TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_remove_unused_locals | TODO_update_ssa_no_phi
#include "gcc-generate-gimple-pass.h"

static bool kernexec_fptr_gate(void)
{
	return kernexec_cmodel_check();
}

#define PASS_NAME kernexec_fptr
#define TODO_FLAGS_FINISH TODO_verify_ssa | TODO_verify_stmts | TODO_dump_func | TODO_remove_unused_locals | TODO_update_ssa_no_phi
#include "gcc-generate-gimple-pass.h"

static bool kernexec_retaddr_gate(void)
{
	return kernexec_cmodel_check();
}

#define PASS_NAME kernexec_retaddr
#define TODO_FLAGS_FINISH TODO_dump_func | TODO_ggc_collect
#include "gcc-generate-rtl-pass.h"

__visible int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	const char * const plugin_name = plugin_info->base_name;
	const int argc = plugin_info->argc;
	const struct plugin_argument * const argv = plugin_info->argv;
	int i;

	PASS_INFO(kernexec_reload, "early_optimizations", 1, PASS_POS_INSERT_BEFORE);
// unfortunately PRE can screw up fptr types from unions...
// see cpuhp_step_startup/cpuhp_step_teardown and kernel.cpu.c:cpuhp_invoke_callback
//	PASS_INFO(kernexec_fptr, "early_optimizations", 1, PASS_POS_INSERT_BEFORE);
	PASS_INFO(kernexec_fptr, "pre", 1, PASS_POS_INSERT_AFTER);
	PASS_INFO(kernexec_retaddr, "pro_and_epilogue", 1, PASS_POS_INSERT_AFTER);

	if (!plugin_default_version_check(version, &gcc_version)) {
		error_gcc_version(version);
		return 1;
	}

	register_callback(plugin_name, PLUGIN_INFO, NULL, &kernexec_plugin_info);

	if (TARGET_64BIT == 0)
		return 0;

	for (i = 0; i < argc; ++i) {
		if (!strcmp(argv[i].key, "method")) {
			if (!argv[i].value) {
				error(G_("no value supplied for option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
				continue;
			}
			if (!strcmp(argv[i].value, "bts") || !strcmp(argv[i].value, "\"bts\"")) {
				kernexec_instrument_fptr = kernexec_instrument_fptr_bts;
				kernexec_instrument_retaddr = kernexec_instrument_retaddr_bts;
			} else if (!strcmp(argv[i].value, "or") || !strcmp(argv[i].value, "\"or\"")) {
				kernexec_instrument_fptr = kernexec_instrument_fptr_or;
				kernexec_instrument_retaddr = kernexec_instrument_retaddr_or;
				fix_register("r12", 1, 1);
			} else
				error(G_("invalid option argument '-fplugin-arg-%s-%s=%s'"), plugin_name, argv[i].key, argv[i].value);
			continue;
		}
		error(G_("unknown option '-fplugin-arg-%s-%s'"), plugin_name, argv[i].key);
	}
	if (!kernexec_instrument_fptr || !kernexec_instrument_retaddr)
		error(G_("no instrumentation method was selected via '-fplugin-arg-%s-method'"), plugin_name);

	if (kernexec_instrument_fptr == kernexec_instrument_fptr_or)
		register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kernexec_reload_pass_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kernexec_fptr_pass_info);
	register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &kernexec_retaddr_pass_info);

	return 0;
}
