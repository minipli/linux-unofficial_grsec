/*
 * Copyright 2012-2016 by PaX Team <pageexec@freemail.hu>
 * Licensed under the GPL v2
 *
 * Homepage: http://pax.grsecurity.net/
 */

#include "rap.h"

static rap_hash_t *rap_imprecise_hashes;
static int rap_cgraph_max_uid;

static void rap_hash_function(const_tree fntype, rap_hash_flags_t flags, unsigned char sip_hash[8]);

static const unsigned char rap_hash_tree_code[MAX_TREE_CODES] = {
	[0] = 0,
	[1] = 0,
	[2] = 0,
	[3] = 0,
	[4] = 0,
	[OFFSET_TYPE] = 10,
	[ENUMERAL_TYPE] = 20,
	[BOOLEAN_TYPE] = 30,
	[INTEGER_TYPE] = 40,
	[REAL_TYPE] = 50,
	[POINTER_TYPE] = 60,
	[REFERENCE_TYPE] = 70,
#if BUILDING_GCC_VERSION >= 4006
	[NULLPTR_TYPE] = 80,
#endif
	[FIXED_POINT_TYPE] = 0,
	[COMPLEX_TYPE] = 100,
	[VECTOR_TYPE] = 110,
	[ARRAY_TYPE] = 120,
	[RECORD_TYPE] = 130,
	[UNION_TYPE] = 140,
	[QUAL_UNION_TYPE] = 0,
	[VOID_TYPE] = 160,
#if BUILDING_GCC_VERSION >= 5000
	[POINTER_BOUNDS_TYPE] = 170,
#endif
	[FUNCTION_TYPE] = 180,
	[METHOD_TYPE] = 0,
	[LANG_TYPE] = 0,
};

static void rap_fold_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
	static const unsigned char rap_sip_key[16] = {
		'P', 'a', 'X', ' ', 'T', 'e', 'a', 'm',
		'R', 'A', 'P', ' ', 'H', 'A', 'S', 'H',
	};

	siphash24fold(out, in, inlen, rap_sip_key);
}

// compute the final hash value in the range [1,INT_MAX]
// the % and +1 trick leaves the value 0 available for marking non-indirectly callable functions
// and INT_MIN (0x80000000) for longjmp targets (sign extended)
// return places will use the (sign extended) range [INT_MIN+1,-1] ([0x8000001,0xffffffff])
static rap_hash_t rap_extract_hash(const unsigned char sip_hash[8])
{
	rap_hash_t hash;
	unsigned long long dividend, divisor;

	memcpy(&dividend, sip_hash, sizeof dividend);
//	divisor = 1ULL << (sizeof hash * 8 - 1);
//	divisor |= divisor - 1;
	divisor = 0x7fffffffUL;
	hash.hash = dividend % divisor + 1;
	return hash;
}

static void rap_hash_type_name(const_tree type, unsigned char sip_hash[8])
{
	const_tree name = type_name(TYPE_MAIN_VARIANT(type));

	// handle typedefs of anonymous structs/unions
	if (name == NULL_TREE)
		name = type_name(type);

	if (name == NULL_TREE)
		return;

	gcc_assert(TREE_CODE(name) == IDENTIFIER_NODE);
	rap_fold_hash(sip_hash, (const unsigned char *)IDENTIFIER_POINTER(name), IDENTIFIER_LENGTH(name));
}

static void rap_hash_type_precision(const_tree type, unsigned char sip_hash[8])
{
	unsigned HOST_WIDE_INT size;

	gcc_assert(TYPE_PRECISION(type));

	size = TYPE_PRECISION(type);
	rap_fold_hash(sip_hash, (const unsigned char *)&size, sizeof size);
}

const_tree type_name(const_tree type)
{
	const_tree name;

	name = TYPE_NAME(type);
	if (!name)
		return NULL_TREE;

	switch (TREE_CODE(name)) {
	case IDENTIFIER_NODE:
		return name;

	case TYPE_DECL:
		gcc_assert(DECL_NAME(name));
		return DECL_NAME(name);

	default:
		gcc_unreachable();
	}
}

// the core computation of the rap hash
// the first piece is a (hopefully) compiler independent encondig of the type, derived from the gcc tree code
// the second piece is type specific information, such as the size, qualifiers, (recursively) referenced types, etc
static void rap_hash_tree(const_tree type, rap_hash_flags_t flags, unsigned char sip_hash[8])
{
	enum tree_code code;
	unsigned int attrs;

	code = TREE_CODE(type);
	attrs = rap_hash_tree_code[code];
	if (!attrs) {
		fprintf(stderr, "unhandled tree_code %s %d\n", get_tree_code_name(code), code);
		debug_tree(type);
		gcc_unreachable();
	}
	rap_fold_hash(sip_hash, (const unsigned char *)&attrs, sizeof attrs);

	enum {
	// attrs layout for
		// - all types:
		RAP_HASH_VOLATILE		= 1U << 31,
		RAP_HASH_NOT_VOLATILE		= 1U << 30,
		RAP_HASH_CONST			= 1U << 29,
		RAP_HASH_NOT_CONST		= 1U << 28,

		// - pointer types:
		RAP_HASH_RESTRICT		= 1U << 27,
		RAP_HASH_NOT_RESTRICT		= 1U << 26,

		// - C integer types:
		RAP_HASH_UNSIGNED		= 1U << 25,
		RAP_HASH_SIGNED			= 1U << 24,

		RAP_HASH_UNQUALIFIED_CHAR	= 1U << 23,
		RAP_HASH_CHAR			= 1U << 22,
		RAP_HASH_SHORT			= 1U << 21,
		RAP_HASH_INT			= 1U << 20,
		RAP_HASH_LONG			= 1U << 19,
		RAP_HASH_LONG_LONG		= 1U << 18,
		RAP_HASH_WCHAR			= 1U << 17,
		RAP_HASH_CHAR16			= 1U << 16,
		RAP_HASH_CHAR32			= 1U << 15,

		// - C float types
		RAP_HASH_FLOAT			= 1U << 14,
		RAP_HASH_DOUBLE			= 1U << 13,
		RAP_HASH_LONG_DOUBLE		= 1U << 12,
		RAP_HASH_DFLOAT32		= 1U << 11,
		RAP_HASH_DFLOAT64		= 1U << 10,
		RAP_HASH_DFLOAT128		= 1U << 9,
	};

	attrs = 0;
	if (flags.qual_volatile)
		attrs |= TYPE_VOLATILE(type) ? RAP_HASH_VOLATILE : RAP_HASH_NOT_VOLATILE;
	if (flags.qual_const)
		attrs |= TYPE_READONLY(type) ? RAP_HASH_CONST : RAP_HASH_NOT_CONST;

	switch (code) {
	default:
		debug_tree(type);
		gcc_unreachable();
		break;

	case VOID_TYPE:
		break;

	case OFFSET_TYPE:
		rap_hash_tree(TREE_TYPE(type), flags, sip_hash);
		rap_hash_tree(TYPE_OFFSET_BASETYPE(type), flags, sip_hash);
		break;

	case FUNCTION_TYPE:
		rap_hash_function(type, flags, sip_hash);
		break;

	case RECORD_TYPE:
		rap_hash_type_name(type, sip_hash);
		break;

	case UNION_TYPE:
		rap_hash_type_name(type, sip_hash);
		break;

	case POINTER_TYPE:
	case REFERENCE_TYPE:
		rap_hash_tree(TREE_TYPE(type), flags, sip_hash);
		break;

	case VECTOR_TYPE:
		rap_hash_tree(TREE_TYPE(type), flags, sip_hash);
		rap_hash_type_precision(TREE_TYPE(type), sip_hash);
		break;

	case ARRAY_TYPE:
		rap_hash_tree(TREE_TYPE(type), flags, sip_hash);
		break;

	case REAL_TYPE: {
		const_tree main_variant = TYPE_MAIN_VARIANT(type);

		switch (TYPE_PRECISION(main_variant)) {
		default:
			debug_tree(type);
			debug_tree(TYPE_MAIN_VARIANT(type));
			gcc_unreachable();

		case 32:
//			attrs |= RAP_HASH_FLOAT;
			break;

		case 64:
//			attrs |= RAP_HASH_DOUBLE;
			break;

		case 80:
		case 128:
			attrs |= RAP_HASH_LONG_DOUBLE;
			break;
		}
		rap_hash_type_precision(main_variant, sip_hash);
		break;
	}

	case ENUMERAL_TYPE:
		rap_hash_type_name(type, sip_hash);
	case BOOLEAN_TYPE:
		rap_hash_type_precision(type, sip_hash);
		break;

	case INTEGER_TYPE: {
		attrs |= TYPE_UNSIGNED(type) ? RAP_HASH_UNSIGNED : RAP_HASH_SIGNED;
		rap_hash_type_precision(type, sip_hash);
		break;
	}
	}

	rap_fold_hash(sip_hash, (const unsigned char *)&attrs, sizeof attrs);
}

static const_tree rap_dequal_argtype(const_tree argtype)
{
	// since gcc/tree.c:free_lang_data_in_type removes const/volatile from the top level param decl
	// we have to simulate it here as this can be called earlier from the frontend as well
	if (TYPE_READONLY(argtype) || TYPE_VOLATILE(argtype)) {
		int quals;

		quals = TYPE_QUALS(argtype) & ~TYPE_QUAL_CONST & ~TYPE_QUAL_VOLATILE;
		argtype = build_qualified_type(CONST_CAST_TREE(argtype), quals);
	}

	return argtype;
}

// main function to compute the rap hash for function types
// while virtual class methods are always replaced with their ancestor,
// callers can decide whether to fully utilize that information via flags.method_ancestor
static void rap_hash_function(const_tree fntype, rap_hash_flags_t flags, unsigned char sip_hash[8])
{
	function_args_iterator args_iter;
	const_tree arg;

	switch (TREE_CODE(fntype)) {
	default:
		debug_tree(fntype);
		gcc_unreachable();

	case FUNCTION_TYPE:
		// 1. hash the result
		rap_hash_tree(TREE_TYPE(fntype), flags, sip_hash);

		// 2. hash the function parameters
		FOREACH_FUNCTION_ARGS(fntype, arg, args_iter) {
			const_tree argtype = arg;

			argtype = rap_dequal_argtype(argtype);
			rap_hash_tree(argtype, flags, sip_hash);
		}
		break;
	}
}

rap_hash_t rap_hash_function_type(const_tree fntype, rap_hash_flags_t flags)
{
	unsigned char sip_hash[8] = { };
	rap_hash_t hash;

	rap_hash_function(fntype, flags, sip_hash);
	hash = rap_extract_hash(sip_hash);

	gcc_assert(hash.hash);
	return hash;
}

rap_hash_t rap_hash_function_decl(const_tree fndecl, rap_hash_flags_t flags)
{
	tree fntype;

	gcc_assert(TREE_CODE(fndecl) == FUNCTION_DECL);
	fntype = TREE_TYPE(fndecl);

	switch (TREE_CODE(fntype)) {
	default:
		debug_tree(fndecl);
		gcc_unreachable();

	case FUNCTION_TYPE:
		return rap_hash_function_type(fntype, flags);
	}
}

rap_hash_t rap_hash_function_node_imprecise(cgraph_node_ptr node)
{
	rap_hash_t hash;
	tree fndecl;

	gcc_assert(rap_imprecise_hashes);

	hash.hash = 0;
	if (node->uid < rap_cgraph_max_uid)
		hash = rap_imprecise_hashes[node->uid];

	if (hash.hash)
		return hash;

	fndecl = NODE_DECL(node);
	if (TREE_CODE(TREE_TYPE(fndecl)) == FUNCTION_TYPE)
		return rap_hash_function_decl(fndecl, imprecise_rap_hash_flags);

	debug_cgraph_node(node);
	debug_tree(fndecl);
	error("indirect call to function %qD with a reserved hash value", fndecl);
	return hash;
}

void rap_calculate_func_hashes(void *event_data __unused, void *data __unused)
{
	cgraph_node_ptr node;
	int uid;

	gcc_assert(!rap_imprecise_hashes);

	rap_imprecise_hashes = (rap_hash_t *)xcalloc(cgraph_max_uid, sizeof(*rap_imprecise_hashes));
	rap_cgraph_max_uid = cgraph_max_uid;

	FOR_EACH_FUNCTION(node) {
		const_tree fndecl;

		uid = node->uid;
		gcc_assert(uid < rap_cgraph_max_uid);

		if (node->global.inlined_to)
			continue;

		fndecl = NODE_DECL(node);
		gcc_assert(fndecl);

		rap_imprecise_hashes[uid] = rap_hash_function_decl(fndecl, imprecise_rap_hash_flags);
		gcc_assert(rap_imprecise_hashes[uid].hash);
	}
}
