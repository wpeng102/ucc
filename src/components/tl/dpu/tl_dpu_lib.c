/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "tl_dpu.h"

/* NOLINTNEXTLINE  params is not used*/
UCC_CLASS_INIT_FUNC(ucc_tl_dpu_lib_t, const ucc_base_lib_params_t *params,
                    const ucc_base_config_t *config)
{
    const ucc_tl_dpu_lib_config_t *tl_dpu_config =
        ucc_derived_of(config, ucc_tl_dpu_lib_config_t);
    UCC_CLASS_CALL_SUPER_INIT(ucc_tl_lib_t, &ucc_tl_dpu.super, &tl_dpu_config->super);
    tl_info(&self->super, "initialized lib object: %p", self);
    return UCC_OK;
}

UCC_CLASS_CLEANUP_FUNC(ucc_tl_dpu_lib_t)
{
    tl_info(&self->super, "finalizing lib object: %p", self);
}

UCC_CLASS_DEFINE(ucc_tl_dpu_lib_t, ucc_tl_lib_t);

ucc_status_t ucc_tl_dpu_get_lib_attr(const ucc_base_lib_t *lib,
                                     ucc_base_lib_attr_t *base_attr)
{
    ucc_tl_lib_attr_t *attr = ucc_derived_of(base_attr, ucc_tl_lib_attr_t);

    attr->super.attr.thread_mode    = UCC_THREAD_MULTIPLE;
    attr->super.attr.coll_types     = UCC_TL_DPU_SUPPORTED_COLLS;
    return UCC_OK;
}
