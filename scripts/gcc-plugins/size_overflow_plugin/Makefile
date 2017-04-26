HOST_EXTRACXXFLAGS += $(call hostcc-option, -fno-ipa-icf)

$(HOSTLIBS)-$(CONFIG_PAX_SIZE_OVERFLOW) += size_overflow_plugin.so
always := $($(HOSTLIBS)-y)

size_overflow_plugin-objs := $(patsubst $(srctree)/$(src)/%.c,%.o,$(wildcard $(srctree)/$(src)/*.c))

quiet_cmd_build_size_overflow_hash = GENHASH  $@
      cmd_build_size_overflow_hash = \
	$(CONFIG_SHELL) $(srctree)/$(src)/generate_size_overflow_hash.sh -s $(patsubst e_%,%,$(patsubst $(obj)/%.h,%,$@))_hash -d $< -o $@

define build_size_overflow_hash
targets += $(addsuffix .h,$(1))
$(srctree)/$(src)/size_overflow_plugin_hash.c: $(addprefix $(obj)/,$(addsuffix .h,$(1)))
$(addprefix $(obj)/,$(addsuffix .h,$(1))): $(addprefix $(src)/,$(addsuffix .data,$(1)))
	$$(call if_changed,build_size_overflow_hash)
endef

size_overflow_hash_tables := e_fns e_fields e_fptrs e_vars e_aux disable
$(foreach h,$(size_overflow_hash_tables),$(eval $(call build_size_overflow_hash,$(h))))

clean-files += *.so
