#
# Copyright (C) Mellanox Technologies Ltd. 2021-2022.  ALL RIGHTS RESERVED.
#

tl_dpu_enabled=n
CHECK_TLS_REQUIRED(["dpu"])
AS_IF([test "$CHECKED_TL_REQUIRED" = "y"],
[
    CHECK_DPU
    AC_MSG_RESULT([DPU support: $dpu_happy])
    if test $dpu_happy = "yes"; then
       tl_modules="${tl_modules}:dpu"
       tl_dpu_enabled=y
       CHECK_NEED_TL_PROFILING(["tl_dpu"])
       AS_IF([test "$TL_PROFILING_REQUIRED" = "y"],
             [
               AC_DEFINE([HAVE_PROFILING_TL_DPU], [1], [Enable profiling for TL DPU])
               prof_modules="${prof_modules}:tl_dpu"
             ], [])
    fi
], [])

AM_CONDITIONAL([TL_DPU_ENABLED], [test "$tl_dpu_enabled" = "y"])
AC_CONFIG_FILES([src/components/tl/dpu/Makefile])
