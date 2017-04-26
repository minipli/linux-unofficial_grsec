$(HOSTLIBS)-$(CONFIG_PAX_RAP) += rap_plugin.so
always := $($(HOSTLIBS)-y)

rap_plugin-objs := $(patsubst $(srctree)/$(src)/%.c,%.o,$(wildcard $(srctree)/$(src)/*.c))

clean-files += *.so
