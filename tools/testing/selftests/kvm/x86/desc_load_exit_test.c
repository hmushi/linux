// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM_CAP_X86_DESC_LOAD_EXIT: a descriptor-table load the capability lists
 * exits to userspace with the decoded operand, without running and without
 * moving RIP.  The same load runs natively once the capability is cleared.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

static struct desc_ptr guest_idt;
static uint64_t guest_lidt_rip, guest_lidt_next;
static uint64_t guest_lldt_rip, guest_lldt_next;

static void guest_code(void)
{
	uint16_t sel = 0;

	/* A store runs as always, with or without the capability. */
	__asm__ __volatile__("sidt %0" : "=m"(guest_idt));

	/* Reload the same table: the load exits, then applies natively. */
	__asm__ __volatile__("lea 1f(%%rip), %%rax\n\t"
			     "mov %%rax, %0\n\t"
			     "lea 2f(%%rip), %%rax\n\t"
			     "mov %%rax, %1\n\t"
			     "1: lidt %2\n\t"
			     "2:"
			     : "=m"(guest_lidt_rip), "=m"(guest_lidt_next)
			     : "m"(guest_idt)
			     : "rax", "memory");
	GUEST_SYNC(1);

	/* Register form: the null selector in RCX, register number 1. */
	__asm__ __volatile__("lea 1f(%%rip), %%rax\n\t"
			     "mov %%rax, %0\n\t"
			     "lea 2f(%%rip), %%rax\n\t"
			     "mov %%rax, %1\n\t"
			     "1: lldt %w2\n\t"
			     "2:"
			     : "=m"(guest_lldt_rip), "=m"(guest_lldt_next)
			     : "c"(sel)
			     : "rax", "memory");
	GUEST_SYNC(2);

	GUEST_DONE();
}

static void assert_desc_load_exit(struct kvm_vcpu *vcpu, uint64_t reg,
				  uint64_t rip, uint64_t next)
{
	struct kvm_run *run = vcpu->run;
	struct kvm_regs regs;

	TEST_ASSERT_EQ(run->exit_reason, KVM_EXIT_PLANE_EVENT);
	TEST_ASSERT_EQ(run->plane_event.cause, KVM_PLANE_EVENT_DESC_LOAD);
	TEST_ASSERT_EQ(run->plane_event.plane, 0);
	TEST_ASSERT_EQ(run->plane_event.extra[0] & KVM_DESC_LOAD_REG_MASK, reg);
	TEST_ASSERT_EQ((run->plane_event.extra[0] & KVM_DESC_LOAD_INSN_LEN_MASK) >>
		       KVM_DESC_LOAD_INSN_LEN_SHIFT, next - rip);
	TEST_ASSERT_EQ(run->plane_event.extra[4], 0);
	TEST_ASSERT_EQ(run->plane_event.extra[7], 0);

	vcpu_regs_get(vcpu, &regs);
	TEST_ASSERT_EQ(regs.rip, rip);
}

static void expect_sync(struct kvm_vcpu *vcpu, uint64_t stage)
{
	struct ucall uc;

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], stage);
}

int main(int argc, char *argv[])
{
	struct kvm_enable_cap bad_cap = { .cap = KVM_CAP_X86_DESC_LOAD_EXIT };
	struct kvm_sregs sregs, after;
	struct kvm_run *run;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	unsigned int mask;

	mask = kvm_check_cap(KVM_CAP_X86_DESC_LOAD_EXIT);
	TEST_REQUIRE(mask & KVM_X86_DESC_LOAD_EXIT_IDTR);
	TEST_REQUIRE(mask & KVM_X86_DESC_LOAD_EXIT_LDTR);

	vm = vm_create_with_one_vcpu(&vcpu, guest_code);
	run = vcpu->run;

	/* A load the host cannot report is refused. */
	bad_cap.args[0] = ~(uint64_t)mask;
	TEST_ASSERT_EQ(__vcpu_ioctl(vcpu, KVM_ENABLE_CAP, &bad_cap), -1);
	TEST_ASSERT_EQ(errno, EINVAL);

	vcpu_enable_cap(vcpu, KVM_CAP_X86_DESC_LOAD_EXIT,
			KVM_X86_DESC_LOAD_EXIT_IDTR);
	vcpu_sregs_get(vcpu, &sregs);

	/* lidt with a memory operand exits; the IDTR and RIP do not move. */
	vcpu_run(vcpu);
	sync_global_from_guest(vm, guest_idt);
	sync_global_from_guest(vm, guest_lidt_rip);
	sync_global_from_guest(vm, guest_lidt_next);
	assert_desc_load_exit(vcpu, KVM_X86_DESC_IDTR, guest_lidt_rip,
			      guest_lidt_next);
	TEST_ASSERT(run->plane_event.extra[0] & KVM_DESC_LOAD_IS_MEMORY_OP,
		    "lidt has a memory operand");
	TEST_ASSERT_EQ(run->plane_event.extra[1], (uint64_t)&guest_idt);
	TEST_ASSERT_EQ(run->plane_event.extra[2], guest_idt.size);
	TEST_ASSERT_EQ(run->plane_event.extra[3], guest_idt.address);
	TEST_ASSERT_EQ(guest_idt.size, sregs.idt.limit);
	TEST_ASSERT_EQ(guest_idt.address, sregs.idt.base);

	vcpu_sregs_get(vcpu, &after);
	TEST_ASSERT_EQ(after.idt.base, sregs.idt.base);
	TEST_ASSERT_EQ(after.idt.limit, sregs.idt.limit);

	/* Running again without a change repeats the exit. */
	vcpu_run(vcpu);
	assert_desc_load_exit(vcpu, KVM_X86_DESC_IDTR, guest_lidt_rip,
			      guest_lidt_next);

	/* Cleared: the same lidt runs natively. */
	vcpu_enable_cap(vcpu, KVM_CAP_X86_DESC_LOAD_EXIT, 0);
	expect_sync(vcpu, 1);
	vcpu_sregs_get(vcpu, &after);
	TEST_ASSERT_EQ(after.idt.base, sregs.idt.base);
	TEST_ASSERT_EQ(after.idt.limit, sregs.idt.limit);

	/* lldt with a register operand exits with the selector. */
	vcpu_enable_cap(vcpu, KVM_CAP_X86_DESC_LOAD_EXIT,
			KVM_X86_DESC_LOAD_EXIT_LDTR);
	vcpu_run(vcpu);
	sync_global_from_guest(vm, guest_lldt_rip);
	sync_global_from_guest(vm, guest_lldt_next);
	assert_desc_load_exit(vcpu, KVM_X86_DESC_LDTR, guest_lldt_rip,
			      guest_lldt_next);
	TEST_ASSERT(!(run->plane_event.extra[0] & KVM_DESC_LOAD_IS_MEMORY_OP),
		    "lldt %%cx has a register operand");
	TEST_ASSERT_EQ(run->plane_event.extra[1], 1);
	TEST_ASSERT_EQ(run->plane_event.extra[2], 0);
	TEST_ASSERT_EQ(run->plane_event.extra[3], 0);

	vcpu_enable_cap(vcpu, KVM_CAP_X86_DESC_LOAD_EXIT, 0);
	expect_sync(vcpu, 2);

	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_DONE);

	kvm_vm_free(vm);
	return 0;
}
