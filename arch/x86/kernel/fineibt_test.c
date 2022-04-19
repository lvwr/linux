// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>

void __fineibt_debug(void);

void fineibt_foo(void) {
  pr_info("FineIBT: dmesg should show a FineIBT violation message.\n");
}

void fineibt_bar(void) {
  pr_info("FineIBT: this first one should run smoothly.\n");
}

static int fineibt_test_init(void)
{
  pr_info("FineIBT test\n");

  __fineibt_debug();

  asm volatile(
    "call fineibt_bar\n"
    "lea fineibt_foo(%%rip), %%rax\n"
    "mov $0xdeadbeef, %%r11\n"
    "call *%%rax\n"
    /* this should trigger the handler because the hash is wrong */
    ::: "rax"
  );
  return 0;
}

static void fineibt_test_exit(void)
{
}

module_init(fineibt_test_init);
module_exit(fineibt_test_exit);

MODULE_LICENSE("GPL v2");
