// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>

static int cet_test_init(void)
{
	pr_info("CET test, expect faults\n");

	// FIXME: use register_die_notifier

	asm volatile(
		"lea 1f(%%rip), %%rax\n"
		"jmp *%%rax\n"
		"nop\n"
		"1:\n"
		/* no endbranch */
		"nop\n"
		:::"rax"
		    );
	return 0;
}

static void cet_test_exit(void)
{
}

module_init(cet_test_init);
module_exit(cet_test_exit);

MODULE_LICENSE("GPL v2");
