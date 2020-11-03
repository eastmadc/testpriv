
# 6.3.2 make didn't have abspath.
# abspath was broken in window's 6.4.1 make.

#abspath_compat=$(abspath $(1))
abspath_compat=$(shell cd $(1) && $(PWD_HOST))

