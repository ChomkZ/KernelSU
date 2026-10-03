/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Bridge between the KernelPatch KPM engine and the KernelSU fork policy
 * layer. Replaces KP's own sucompat/kstorage include pair.
 */
#ifndef _KP_KPM_KSU_COMPAT_H_
#define _KP_KPM_KSU_COMPAT_H_

#include <linux/types.h>
#include <linux/uidgid.h>

#include "policy/allowlist.h"
#include "manager/manager_identity.h"

/* KP sucompat equivalent: uid allowed (root in ksu domain or allowlisted). */
static inline int kp_is_su_allow_uid(uid_t uid)
{
	return ksu_is_allow_uid_for_current(uid) ? 1 : 0;
}

/* KP kstorage-backed exclude list: not supported by the KernelSU fork.
 * Mirrors SukiSU's compact.c behaviour (get -> 0, set -> no-op). */
static inline int kp_su_get_ap_mod_exclude(uid_t uid)
{
	(void)uid;
	return 0;
}

static inline int kp_su_set_ap_mod_exclude(uid_t uid, int exclude)
{
	(void)uid;
	(void)exclude;
	return 0;
}

/* KP manager auth: the trusted manager appid (root domain passes too via
 * the allow check in supercall.c). */
static inline int kp_is_manager_uid(uid_t uid)
{
	return ksu_is_manager_appid_valid() && is_uid_manager(uid);
}

#endif /* _KP_KPM_KSU_COMPAT_H_ */
