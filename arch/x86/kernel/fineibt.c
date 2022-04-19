// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file contains the FineIBT handler function.
 */

#include <linux/export.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include<linux/spinlock.h>
#include <asm/ibt.h>

void __noendbr __fineibt_handler(void);

void __fineibt_debug(void) {
	asm volatile ("nop\n");
	printk("fineibt debug\n");
};
EXPORT_SYMBOL(__fineibt_debug);

#define FINEIBT_VADDR_LEN 4096
#define DO_ALL_PUSHS    \
	asm("nop\n\t"         \
	    "push %rsi\n\t"   \
	    "push %rdi\n\t"   \
	    "push %rdx\n\t"   \
	    "push %rcx\n\t"   \
	    "push %rbx\n\t"   \
	    "push %rax\n\t"   \
	    "push %r8\n\t"    \
	    "push %r9\n\t"    \
	    "push %r10\n\t"   \
	    "push %r11\n\t"   \
	    "push %r12\n\t"   \
	    "push %r13\n\t"   \
	    "push %r14\n\t"   \
	    "push %r15\n\t")

#define DO_ALL_POPS    \
	asm("nop\n\t"        \
	    "pop %r15\n\t"   \
	    "pop %r14\n\t"   \
	    "pop %r13\n\t"   \
	    "pop %r12\n\t"   \
	    "pop %r11\n\t"   \
	    "pop %r10\n\t"   \
	    "pop %r9\n\t"    \
	    "pop %r8\n\t"    \
	    "pop %rax\n\t"   \
	    "pop %rbx\n\t"   \
	    "pop %rcx\n\t"   \
	    "pop %rdx\n\t"   \
	    "pop %rdi\n\t"   \
	    "pop %rsi\n\t")

struct fineibt_violation{
	void * vaddr;
	void * caddr;
	bool printed;
};

typedef struct fineibt_violation fineibt_violation;

static fineibt_violation vlts[FINEIBT_VADDR_LEN];
static unsigned long vlts_next = 0;
static bool vlts_initialize = true;
static DEFINE_SPINLOCK(fineibt_lock);

void __noendbr __fineibt_handler(void){
	unsigned i;
	unsigned long flags;
	bool skip;
	void * ret;
	void * caller;

	DO_ALL_PUSHS;

	spin_lock_irqsave(&fineibt_lock, flags);
	skip = false;

	asm("\t movq 0x90(%%rsp),%0" : "=r"(ret));
	asm("\t movq 0x98(%%rsp),%0" : "=r"(caller));

	if(vlts_initialize){
		for(i = 0; i < FINEIBT_VADDR_LEN; i++) {
			vlts[i].vaddr = 0;
			vlts[i].caddr = 0;
			vlts[i].printed = 0;
		}
		vlts_initialize = false;
	}

	if(vlts_next >= FINEIBT_VADDR_LEN) {
		if(vlts_next == FINEIBT_VADDR_LEN) {
			printk("FineIBT reached max buffer\n");
			vlts_next++;
		}
		skip = true;
	}

	for(i = 0; i < vlts_next; i++){
		if(vlts[i].vaddr == ret && vlts[i].caddr == caller) {
			skip = true;
			break;
		}
	}

	if(!skip) {
		vlts[vlts_next].vaddr = ret;
		vlts[vlts_next].caddr = caller;
		vlts[vlts_next].printed = 0;
		vlts_next = vlts_next + 1;
	}

	spin_unlock_irqrestore(&fineibt_lock, flags);

	if(!skip) {
		printk("FineIBT violation: %px:%px:%u\n", ret, caller,
				vlts_next);
	}
	DO_ALL_POPS;
}

EXPORT_SYMBOL(__fineibt_handler);
