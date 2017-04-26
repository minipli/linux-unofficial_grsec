GCC_PLUGINS_DIR := $(shell $(CC) -print-file-name=plugin)

ifeq ($(PLUGINCC),$(HOSTCC))
  HOSTLIBS := hostlibs
  HOST_EXTRACFLAGS += -I$(GCC_PLUGINS_DIR)/include -I$(src)
  HOST_EXTRACFLAGS += -std=gnu99 -ggdb -fvisibility=hidden
  HOST_EXTRACFLAGS += -Wall -W
  export HOST_EXTRACFLAGS
else
  HOSTLIBS := hostcxxlibs
  HOST_EXTRACXXFLAGS += -I$(GCC_PLUGINS_DIR)/include -I$(src)
  HOST_EXTRACXXFLAGS += -std=gnu++98 -ggdb -fvisibility=hidden
  HOST_EXTRACXXFLAGS += -fno-rtti -fno-exceptions -fasynchronous-unwind-tables
  HOST_EXTRACXXFLAGS += -Wall -W
  HOST_EXTRACXXFLAGS += -Wno-unused-parameter -Wno-narrowing -Wno-unused-variable
  export HOST_EXTRACXXFLAGS
endif

ifneq ($(CFLAGS_KCOV), $(SANCOV_PLUGIN))
  GCC_PLUGIN := $(filter-out $(SANCOV_PLUGIN), $(GCC_PLUGIN))
endif

export HOSTLIBS

$(HOSTLIBS)-y := $(foreach p,$(GCC_PLUGIN),$(if $(findstring /,$(p)),,$(p)))
always := $($(HOSTLIBS)-y)
$(foreach p,$($(HOSTLIBS)-y:%.so=%),$(eval $(p)-objs := $(p).o))

$(obj)/randomize_layout_plugin.o: $(objtree)/$(obj)/randomize_layout_seed.h

quiet_cmd_create_randomize_layout_seed = GENSEED  $@
	cmd_create_randomize_layout_seed = \
	$(CONFIG_SHELL) $(srctree)/$(src)/gen-random-seed.sh $@ $(objtree)/include/generated/randomize_layout_hash.h
$(objtree)/$(obj)/randomize_layout_seed.h: FORCE
	$(call if_changed,create_randomize_layout_seed)
 
targets += randomize_layout_seed.h randomize_layout_hash.h

subdir-y := $(GCC_PLUGIN_SUBDIR)
subdir-  += $(GCC_PLUGIN_SUBDIR)

clean-files += *.so
