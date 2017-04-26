#ifndef SIZE_OVERFLOW_H
#define SIZE_OVERFLOW_H

#define CREATE_NEW_VAR NULL_TREE
#define MAX_PARAM 31
#define CANNOT_FIND_ARG 32
#define NONE_ARGNUM 32

#define BEFORE_STMT true
#define AFTER_STMT false

#define TURN_OFF_ASM_STR "# size_overflow MARK_TURN_OFF "
#define YES_ASM_STR "# size_overflow MARK_YES "
#define END_INTENTIONAL_ASM_STR "# size_overflow MARK_END_INTENTIONAL "
#define SO_ASM_STR "# size_overflow "
#define OK_ASM_STR "# size_overflow MARK_NO"

#define FUNCTION_PTR_P(node) \
	(TREE_CODE(TREE_TYPE(node)) == POINTER_TYPE && (TREE_CODE(TREE_TYPE(TREE_TYPE(node))) == FUNCTION_TYPE || TREE_CODE(TREE_TYPE(TREE_TYPE(node))) == METHOD_TYPE))

#define CODES_LIMIT 32

#define GLOBAL_NIFN_LEN 65536
#define NO_HASH 65537

#define SIZE_OVERFLOW true
#define DISABLE_SIZE_OVERFLOW false

#include "gcc-common.h"

#include <string.h>
#include <limits.h>

enum intentional_mark {
	MARK_NO, MARK_YES, MARK_END_INTENTIONAL, MARK_TURN_OFF
};

enum intentional_overflow_type {
	NO_INTENTIONAL_OVERFLOW, RHS1_INTENTIONAL_OVERFLOW, RHS2_INTENTIONAL_OVERFLOW
};

enum size_overflow_mark {
	NO_SO_MARK, YES_SO_MARK, ASM_STMT_SO_MARK
};

struct decl_hash {
	size_t tree_codes_len;
	unsigned char tree_codes[CODES_LIMIT];
	const_tree decl;
	const char *context;
	unsigned int hash;
	const char *fn_name;
};

struct next_interesting_function;
typedef struct next_interesting_function *  next_interesting_function_t;

struct interesting_stmts;
typedef struct interesting_stmts * interesting_stmts_t;

enum based_decl {
	SO_FUNCTION, SO_VAR, SO_FIELD, SO_FUNCTION_POINTER, SO_AUX, SO_DISABLE, SO_NONE
};

// Store data associated with the next_interesting_function_t entry
struct fn_raw_data
{
	const char *decl_str;
	tree decl;
	const char *context;
	unsigned int hash;
	unsigned int num;
	enum size_overflow_mark marked;
	enum based_decl based_decl;
	const char *orig_decl_str;
	unsigned int orig_num;
};

#if BUILDING_GCC_VERSION <= 4007
DEF_VEC_P(next_interesting_function_t);
DEF_VEC_ALLOC_P(next_interesting_function_t, heap);
#endif

#if BUILDING_GCC_VERSION >= 5000
typedef struct hash_set<const_gimple> gimple_set;

static inline bool pointer_set_insert(gimple_set *visited, const_gimple stmt)
{
	return visited->add(stmt);
}

static inline bool pointer_set_contains(gimple_set *visited, const_gimple stmt)
{
	return visited->contains(stmt);
}

static inline gimple_set* pointer_set_create(void)
{
	return new hash_set<const_gimple>;
}

static inline void pointer_set_destroy(gimple_set *visited)
{
	delete visited;
}

typedef struct hash_set<next_interesting_function_t> next_interesting_function_set;

static inline bool pointer_set_insert(next_interesting_function_set *visited, next_interesting_function_t node)
{
	return visited->add(node);
}

static inline bool pointer_set_contains(next_interesting_function_set *visited, next_interesting_function_t node)
{
	return visited->contains(node);
}

static inline next_interesting_function_set *next_interesting_function_pointer_set_create(void)
{
	return new hash_set<next_interesting_function_t>;
}

static inline void pointer_set_destroy(next_interesting_function_set *visited)
{
	delete visited;
}
#else
typedef struct pointer_set_t gimple_set;
typedef struct pointer_set_t next_interesting_function_set;

static inline next_interesting_function_set *next_interesting_function_pointer_set_create(void)
{
	return pointer_set_create();
}
#endif

struct visited {
	gimple_set *stmts;
	gimple_set *my_stmts;
	gimple_set *skip_expr_casts;
	gimple_set *no_cast_check;
};

/*
 *  * children: callers with data flow into the integer parameter of decl
 *  * decl_name: name of the function or the field
 *  * context: the containing type name for a function pointer (or "fielddecl" if the type has no name), otherwise either "vardecl" or "fndecl"
 *  * hash: hash num of the function
 *  * num: parameter number (1-31) or return value (0)
 *  * marked: determines whether to duplicate stmts and/or look for missing hashtable entries
 *  * orig_next_node: pointer to the originally cloned function
 */

struct next_interesting_function {
	next_interesting_function_t next;
#if BUILDING_GCC_VERSION <= 4007
	VEC(next_interesting_function_t, heap) *children;
#else
	vec<next_interesting_function_t, va_heap, vl_embed> *children;
#endif
	const char *decl_name;
	const char *context;
	enum based_decl based_decl;
	unsigned int hash;
	unsigned int num;
	enum size_overflow_mark marked;
	next_interesting_function_t orig_next_node;
};

// size_overflow_plugin.c
extern tree report_size_overflow_decl;
extern tree size_overflow_type_HI;
extern tree size_overflow_type_SI;
extern tree size_overflow_type_DI;
extern tree size_overflow_type_TI;
// command line options
extern bool check_fields, check_fns, check_fnptrs, check_vars;


// size_overflow_plugin_hash.c
struct size_overflow_hash {
	const struct size_overflow_hash * const next;
	const char * const name;
	const char * const context;
	const unsigned int param;
};

extern const char *get_orig_decl_name(const_tree decl);
extern bool is_size_overflow_asm(const_gimple stmt);
extern void print_missing_function(next_interesting_function_t node);
extern const struct size_overflow_hash *get_size_overflow_hash_entry(struct fn_raw_data *raw_data);
extern const struct size_overflow_hash *get_size_overflow_hash_entry_tree(struct fn_raw_data *raw_data, bool hash_table);
extern unsigned int find_arg_number_tree(const_tree arg, const_tree func);
extern unsigned int get_decl_hash(const_tree decl, const char *decl_name);
extern const char *get_based_decl_str(enum based_decl based_decl);
extern void initialize_raw_data(struct fn_raw_data *raw_data);


// intentional_overflow.c
extern enum intentional_mark get_intentional_attr_type(const_tree node);
extern tree get_size_overflow_asm_input(const gasm *stmt);
extern enum intentional_mark check_intentional_size_overflow_asm_and_attribute(const_tree var);
extern bool is_size_overflow_insert_check_asm(const gasm *stmt);
extern enum intentional_mark check_intentional_attribute(const_gimple stmt, unsigned int argnum);
extern enum intentional_mark get_so_asm_type(const_gimple stmt);
extern const_tree get_attribute(const char* attr_name, const_tree decl);
extern bool is_a_cast_and_const_overflow(const_tree no_const_rhs);
extern bool is_const_plus_unsigned_signed_truncation(const_tree lhs);
extern bool is_a_constant_overflow(const gassign *stmt, const_tree rhs);
extern tree handle_intentional_overflow(interesting_stmts_t expand_from, bool check_overflow, gassign *stmt, tree change_rhs, tree new_rhs2);
extern tree handle_integer_truncation(interesting_stmts_t expand_from, const_tree lhs);
extern bool is_a_neg_overflow(const gassign *stmt, const_tree rhs);
extern enum intentional_overflow_type add_mul_intentional_overflow(const gassign *stmt);
extern void unsigned_signed_cast_intentional_overflow(struct visited *visited, gassign *stmt);
extern bool neg_short_add_intentional_overflow(gassign *stmt);
extern bool is_bitfield_unnamed_cast(const_tree decl, gassign *assign);
extern bool uconst_neg_intentional_overflow(const gassign *stmt);
extern bool short_or_neg_const_ushort(gassign *stmt);


// insert_size_overflow_asm.c
#if BUILDING_GCC_VERSION >= 4009
extern opt_pass *make_insert_size_overflow_asm_pass(void);
#else
extern struct opt_pass *make_insert_size_overflow_asm_pass(void);
#endif
extern bool search_interesting_args(tree fndecl, bool *argnums);


// size_overflow_misc.c
extern bool is_vararg(const_tree fn, unsigned int num);
extern tree get_ref_field(const_tree ref);
extern unsigned int get_correct_argnum_fndecl(const_tree fndecl, const_tree correct_argnum_of_fndecl, unsigned int num);
extern const char *get_type_name_from_field(const_tree field_decl);
extern void set_dominance_info(void);
extern void unset_dominance_info(void);
extern tree get_interesting_orig_fndecl_from_stmt(const gcall *stmt);
extern tree get_orig_fndecl(const_tree clone_fndecl);
extern unsigned int get_correct_argnum(const_tree decl, const_tree correct_argnum_of_decl, unsigned int argnum);
extern bool is_valid_cgraph_node(struct cgraph_node *node);
extern void set_current_function_decl(tree fndecl);
extern void unset_current_function_decl(void);
extern gimple get_def_stmt(const_tree node);
extern tree create_new_var(tree type);
extern gimple build_cast_stmt(struct visited *visited, tree dst_type, tree rhs, tree lhs, gimple_stmt_iterator *gsi, bool before, bool force);
extern bool skip_types(const_tree var);
extern tree cast_a_tree(tree type, tree var);
extern bool is_size_overflow_type(const_tree var);
extern bool made_by_compiler(const_tree decl);
extern gimple get_fnptr_def_stmt(const_tree fn_ptr);
extern tree get_lhs(const_gimple stmt);


// size_overflow_transform.c
struct interesting_stmts {
	struct interesting_stmts *next;
	next_interesting_function_t next_node;
	gimple first_stmt;
	tree orig_node;
	unsigned int num;
	struct visited *visited;
};

extern unsigned int size_overflow_function_transform(struct cgraph_node *node);
extern tree handle_fnptr_assign(const_gimple stmt);


// size_overflow_transform_core.c
extern tree cast_to_new_size_overflow_type(struct visited *visited, gimple stmt, tree rhs, tree size_overflow_type, bool before);
extern tree get_size_overflow_type(struct visited *visited, const_gimple stmt, const_tree node);
extern tree expand(interesting_stmts_t expand_from, tree lhs);
extern void check_size_overflow(interesting_stmts_t expand_from, gimple stmt, tree size_overflow_type, tree cast_rhs, tree rhs, bool before);
extern tree dup_assign(struct visited *visited, gassign *oldstmt, const_tree node, tree rhs1, tree rhs2, tree __unused rhs3);
extern tree create_assign(struct visited *visited, gimple oldstmt, tree rhs1, bool before);


// remove_unnecessary_dup.c
extern struct opt_pass *make_remove_unnecessary_dup_pass(void);
extern void insert_cast_expr(struct visited *visited, gassign *stmt, enum intentional_overflow_type type);
extern bool skip_expr_on_double_type(const gassign *stmt);
extern void create_up_and_down_cast(struct visited *visited, gassign *use_stmt, tree orig_type, tree rhs);


// size_overflow_ipa.c
struct walk_use_def_data {
	next_interesting_function_t parent;
	next_interesting_function_t next_cnodes_head;
	gimple_set *visited;
};

extern const char* get_decl_context(const_tree decl);
extern void add_to_global_next_interesting_function(next_interesting_function_t new_entry);
extern bool has_next_interesting_function_vec(next_interesting_function_t target, next_interesting_function_t next_node);
extern void push_child(next_interesting_function_t parent, next_interesting_function_t child);
extern struct cgraph_node *get_cnode(const_tree fndecl);
extern next_interesting_function_t global_next_interesting_function[GLOBAL_NIFN_LEN];
extern next_interesting_function_t get_global_next_interesting_function_entry(struct fn_raw_data *raw_data);
extern next_interesting_function_t get_global_next_interesting_function_entry_with_hash(struct fn_raw_data *raw_data);
extern void size_overflow_register_hooks(void);
#if BUILDING_GCC_VERSION >= 4009
extern opt_pass *make_size_overflow_pass(void);
#else
extern struct opt_pass *make_size_overflow_pass(void);
#endif
extern void size_overflow_node_removal_hook(struct cgraph_node *node, void *data);
extern next_interesting_function_t get_and_create_next_node_from_global_next_nodes(struct fn_raw_data *raw_data, next_interesting_function_t orig_next_node);
extern next_interesting_function_t create_new_next_interesting_decl(struct fn_raw_data *raw_data, next_interesting_function_t orig_next_node);
extern next_interesting_function_t create_new_next_interesting_entry(struct fn_raw_data *raw_data, next_interesting_function_t orig_next_node);


// size_overflow_lto.c
extern void size_overflow_read_summary(void);
extern void size_overflow_read_optimization_summary(void);
#if BUILDING_GCC_VERSION >= 4008
extern void size_overflow_write_summary(void);
extern void size_overflow_write_optimization_summary(void);
#elif BUILDING_GCC_VERSION >= 4006
extern void size_overflow_write_summary(cgraph_node_set set, varpool_node_set vset);
extern void size_overflow_write_optimization_summary(cgraph_node_set set, varpool_node_set vset);
#else
extern void size_overflow_write_summary(cgraph_node_set set);
extern void size_overflow_write_optimization_summary(cgraph_node_set set);
#endif

// size_overflow_fnptrs.c
extern void handle_function_ptr_ret(struct walk_use_def_data *use_def_data, const_tree fn_ptr);
extern void check_local_variables(next_interesting_function_t next_node);
extern void check_global_variables(next_interesting_function_t cur_global);
extern next_interesting_function_t get_and_create_next_node_from_global_next_nodes_fnptr(const_tree fn_ptr, struct fn_raw_data *raw_data);


// size_overflow_debug.c
extern void __unused print_intentional_mark(enum intentional_mark mark);
extern unsigned int __unused size_overflow_dump_function(FILE *file, struct cgraph_node *node);
extern void __unused print_next_interesting_functions_chain(next_interesting_function_t head, bool only_this);
extern void __unused print_global_next_interesting_functions(void);
extern void __unused print_children_chain_list(next_interesting_function_t next_node);
extern void __unused print_all_next_node_children_chain_list(next_interesting_function_t next_node);
extern const char * __unused print_so_mark_name(enum size_overflow_mark mark);
extern const char * __unused print_intentional_mark_name(enum intentional_mark mark);
extern void __unused print_next_interesting_function(next_interesting_function_t node);
extern void __unused print_raw_data(struct fn_raw_data *data);

#endif
