// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Test for x86-specific VM plane functionality
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_util.h"

#include "kvm_util.h"
#include "processor.h"
#include "apic.h"
#include "asm/kvm.h"
#include "linux/kvm.h"

static void test_plane_regs(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_plane *plane;
	struct kvm_plane_vcpu *plane_vcpu;

	struct kvm_regs regs0, regs1;

	vm = vm_create_barebones_irqchip(true);
	vcpu = __vm_vcpu_add(vm, 0);
	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	vcpu_ioctl(vcpu, KVM_GET_REGS, &regs0);
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_REGS, &regs1);
	regs0.rax = 0x12345678;
	regs1.rax = 0x87654321;

	vcpu_ioctl(vcpu, KVM_SET_REGS, &regs0);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_REGS, &regs1);

	vcpu_ioctl(vcpu, KVM_GET_REGS, &regs0);
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_REGS, &regs1);
	TEST_ASSERT_EQ(regs0.rax, 0x12345678);
	TEST_ASSERT_EQ(regs1.rax, 0x87654321);

	kvm_vm_free(vm);
	ksft_test_result_pass("get/set regs for planes\n");
}

/* Offset of XMM0 in the legacy XSAVE area.  */
#define XSTATE_BV_OFFSET	(0x200/4)
#define XMM_OFFSET		(0xa0/4)
#define PKRU_OFFSET		(0xa80/4)

static void test_plane_fpu_nonshared(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_plane *plane;
	struct kvm_plane_vcpu *plane_vcpu;

	struct kvm_xsave xsave0, xsave1;

	vm = vm_create_barebones_irqchip(true);

	vcpu = __vm_vcpu_add(vm, 0);
	vcpu_init_cpuid(vcpu, kvm_get_supported_cpuid());
	vcpu_set_cpuid(vcpu);

	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	vcpu_ioctl(vcpu, KVM_GET_XSAVE, &xsave0);
	xsave0.region[XSTATE_BV_OFFSET] |= XFEATURE_MASK_FP | XFEATURE_MASK_SSE;
	xsave0.region[XMM_OFFSET] = 0x12345678;
	vcpu_ioctl(vcpu, KVM_SET_XSAVE, &xsave0);

	plane_vcpu_ioctl(plane_vcpu, KVM_GET_XSAVE, &xsave1);
	xsave1.region[XSTATE_BV_OFFSET] |= XFEATURE_MASK_FP | XFEATURE_MASK_SSE;
	xsave1.region[XMM_OFFSET] = 0x87654321;
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_XSAVE, &xsave1);

	memset(&xsave0, 0, sizeof(xsave0));
	vcpu_ioctl(vcpu, KVM_GET_XSAVE, &xsave0);
	TEST_ASSERT_EQ(xsave0.region[XMM_OFFSET], 0x12345678);

	memset(&xsave1, 0, sizeof(xsave0));
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_XSAVE, &xsave1);
	TEST_ASSERT_EQ(xsave1.region[XMM_OFFSET], 0x87654321);

	ksft_test_result_pass("get/set FPU not shared across planes\n");
}

#define APIC_SPIV		0xF0
#define APIC_IRR		0x200

#define MYVEC			192

#define MAKE_MSI(cpu, vector) ((struct kvm_msi){			\
	.address_lo = APIC_DEFAULT_GPA + (((cpu) & 0xff) << 8),		\
	.address_hi = (cpu) & ~0xff,					\
	.data = (vector),						\
})

static bool has_irr(struct kvm_lapic_state *apic, int vector)
{
	int word = vector >> 5;
	int bit_in_word = vector & 31;
	int bit = (APIC_IRR + word * 16) * CHAR_BIT + (bit_in_word & 31);

	return apic->regs[bit >> 3] & (1 << (bit & 7));
}

static void do_enable_lapic(struct kvm_lapic_state *apic)
{
	/* set bit 8 */
	apic->regs[APIC_SPIV + 1] |= 1;
}

static void test_plane_msi(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_plane *plane;
	struct kvm_plane_vcpu *plane_vcpu;
	int r;

	struct kvm_msi msi = MAKE_MSI(0, MYVEC);
	struct kvm_lapic_state lapic0, lapic1;

	vm = vm_create_barebones_irqchip(true);

	vcpu = __vm_vcpu_add(vm, 0);
	vcpu_init_cpuid(vcpu, kvm_get_supported_cpuid());
	vcpu_set_cpuid(vcpu);

	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	vcpu_set_msr(vcpu, MSR_IA32_APICBASE,
		     APIC_DEFAULT_GPA | MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);
	vcpu_ioctl(vcpu, KVM_GET_LAPIC, &lapic0);
	do_enable_lapic(&lapic0);
	vcpu_ioctl(vcpu, KVM_SET_LAPIC, &lapic0);

	_plane_vcpu_set_msr(plane_vcpu, MSR_IA32_APICBASE,
			    APIC_DEFAULT_GPA | MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_LAPIC, &lapic1);
	do_enable_lapic(&lapic1);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_LAPIC, &lapic1);

	/* Deliver to plane 1 (via the plane fd); it must land only in plane 1. */
	r = __plane_ioctl(plane, KVM_SIGNAL_MSI, &msi);
	TEST_ASSERT(r == 1,
		   "Delivering interrupt to plane 1. ret: %d, errno: %d", r, errno);

	vcpu_ioctl(vcpu, KVM_GET_LAPIC, &lapic0);
	TEST_ASSERT(!has_irr(&lapic0, MYVEC), "Vector clear in plane 0");
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_LAPIC, &lapic1);
	TEST_ASSERT(has_irr(&lapic1, MYVEC), "Vector set in plane 1");

	/* Deliver to plane 0 (via the vm fd); it must land in plane 0. */
	r = __vm_ioctl(vm, KVM_SIGNAL_MSI, &msi);
	TEST_ASSERT(r == 1,
		   "Delivering interrupt to plane 0. ret: %d, errno: %d", r, errno);
	vcpu_ioctl(vcpu, KVM_GET_LAPIC, &lapic0);
	TEST_ASSERT(has_irr(&lapic0, MYVEC), "Vector set in plane 0");

	kvm_vm_free(vm);
	ksft_test_result_pass("signal MSI routed per plane\n");
}

/*
 * MP_STATE is per plane vCPU: a plane vCPU whose id is not the BSP's starts
 * uninitialized while its plane-0 sibling runs; setting it does not touch the
 * sibling; an INIT signalled to the plane's LAPIC is accepted on the plane fd.
 */
static void test_plane_mp_state(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu0, *vcpu1;
	struct kvm_plane *plane;
	struct kvm_plane_vcpu *plane_vcpu0, *plane_vcpu1;
	struct kvm_mp_state mp_state;
	struct kvm_msi init_msi = MAKE_MSI(1, 0);
	int r;

	vm = vm_create_barebones_irqchip(true);

	vcpu0 = __vm_vcpu_add(vm, 0);
	vcpu_init_cpuid(vcpu0, kvm_get_supported_cpuid());
	vcpu_set_cpuid(vcpu0);
	vcpu1 = __vm_vcpu_add(vm, 1);
	vcpu_init_cpuid(vcpu1, kvm_get_supported_cpuid());
	vcpu_set_cpuid(vcpu1);

	plane = vm_plane_add(vm, 1);
	plane_vcpu0 = __vm_plane_vcpu_add(vcpu0, plane);
	plane_vcpu1 = __vm_plane_vcpu_add(vcpu1, plane);

	/* BSP id starts runnable in every plane, the others uninitialized. */
	plane_vcpu_ioctl(plane_vcpu0, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_RUNNABLE);
	plane_vcpu_ioctl(plane_vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_UNINITIALIZED);
	vcpu_ioctl(vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_UNINITIALIZED);

	/* Setting plane 1's state leaves plane 0's alone, and vice versa. */
	mp_state.mp_state = KVM_MP_STATE_RUNNABLE;
	plane_vcpu_ioctl(plane_vcpu1, KVM_SET_MP_STATE, &mp_state);
	vcpu_ioctl(vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_UNINITIALIZED);
	plane_vcpu_ioctl(plane_vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_RUNNABLE);

	mp_state.mp_state = KVM_MP_STATE_HALTED;
	vcpu_ioctl(vcpu1, KVM_SET_MP_STATE, &mp_state);
	plane_vcpu_ioctl(plane_vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_RUNNABLE);

	mp_state.mp_state = KVM_MP_STATE_INIT_RECEIVED;
	plane_vcpu_ioctl(plane_vcpu1, KVM_SET_MP_STATE, &mp_state);
	plane_vcpu_ioctl(plane_vcpu1, KVM_GET_MP_STATE, &mp_state);
	TEST_ASSERT_EQ(mp_state.mp_state, KVM_MP_STATE_INIT_RECEIVED);

	/* An INIT to the plane's LAPIC is accepted on the plane fd. */
	init_msi.data |= APIC_DM_INIT;
	r = __plane_ioctl(plane, KVM_SIGNAL_MSI, &init_msi);
	TEST_ASSERT(r == 1, "INIT to plane 1 vCPU 1. ret: %d, errno: %d", r, errno);

	kvm_vm_free(vm);
	ksft_test_result_pass("MP_STATE per plane vCPU\n");
}

static void guest_plane0(void)
{
	for (;;)
		GUEST_SYNC(0);
}

static void guest_plane1(void)
{
	for (;;)
		GUEST_SYNC(1);
}

/*
 * KVM_CAP_PLANES_USERSPACE_SWITCH: kvm_run->plane picks the plane that runs,
 * and an interrupt pending for a plane in req_exit_planes exits with
 * KVM_EXIT_PLANE_EVENT / KVM_PLANE_EVENT_INTERRUPT instead of running on.
 */
static void test_plane_userspace_switch(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_plane *plane;
	struct kvm_plane_vcpu *plane_vcpu;
	struct kvm_msi msi = MAKE_MSI(0, MYVEC);
	struct kvm_lapic_state lapic1;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct ucall uc;
	int r;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_PLANES_USERSPACE_SWITCH));

	/* Planes need a split IRQ chip; the cap must precede the first vCPU. */
	kvm_force_split_irqchip = true;
	vm = __vm_create(VM_SHAPE_DEFAULT, 1, 0);
	kvm_force_split_irqchip = false;
	vm_enable_cap(vm, KVM_CAP_PLANES_USERSPACE_SWITCH, 0);

	vcpu = vm_vcpu_add(vm, 0, guest_plane0);
	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	/* Plane 1 shares the address space; give it plane 0's state and its own entry. */
	vcpu_sregs_get(vcpu, &sregs);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_SREGS, &sregs);
	vcpu_regs_get(vcpu, &regs);
	regs.rip = (unsigned long)guest_plane1;
	/* Same address space; a stack of its own keeps the planes' frames apart. */
	regs.rsp = vm_alloc_stack(vm, DEFAULT_STACK_PGS);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_REGS, &regs);
	_plane_vcpu_set_msr(plane_vcpu, MSR_IA32_APICBASE,
			    APIC_DEFAULT_GPA | MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_LAPIC, &lapic1);
	do_enable_lapic(&lapic1);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_LAPIC, &lapic1);

	/* Plane 0 runs by default and reports itself. */
	vcpu->run->plane = 0;
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], 0);
	TEST_ASSERT_EQ(vcpu->run->plane, 0);

	/* Userspace asks for plane 1: its code runs on the same KVM_RUN. */
	vcpu->run->plane = 1;
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], 1);
	TEST_ASSERT_EQ(vcpu->run->plane, 1);

	/* A plane that does not exist is refused. */
	vcpu->run->plane = 2;
	r = _vcpu_run(vcpu);
	TEST_ASSERT(r == -1 && errno == EINVAL, "KVM_RUN plane 2: ret %d errno %d", r, errno);

	/*
	 * Back on plane 0 with plane 1 in req_exit_planes: a pending interrupt
	 * for plane 1 exits instead of letting plane 0 run.
	 */
	r = __plane_ioctl(plane, KVM_SIGNAL_MSI, &msi);
	TEST_ASSERT(r == 1, "MSI to plane 1. ret: %d, errno: %d", r, errno);
	vcpu->run->plane = 0;
	vcpu->run->req_exit_planes = BIT(1);
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_PLANE_EVENT);
	TEST_ASSERT_EQ(vcpu->run->plane_event.cause, KVM_PLANE_EVENT_INTERRUPT);
	TEST_ASSERT_EQ(vcpu->run->plane_event.plane, 0);
	TEST_ASSERT_EQ(vcpu->run->plane_event.extra[0], BIT(1));
	TEST_ASSERT_EQ(vcpu->run->plane, 0);

	/* Without the request plane 0 simply runs. */
	vcpu->run->req_exit_planes = 0;
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], 0);

	kvm_vm_free(vm);
	ksft_test_result_pass("userspace plane switch and interrupt exit\n");
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm = vm_create_barebones_irqchip(true);
	int cap_planes = vm_check_cap(vm, KVM_CAP_PLANES);

	kvm_vm_free(vm);
	TEST_REQUIRE(cap_planes && cap_planes > 1);

	ksft_print_header();
	ksft_set_plan(5);

	pr_info("# KVM_CAP_PLANES: %d\n", cap_planes);

	test_plane_regs();
	test_plane_fpu_nonshared();
	test_plane_msi();
	test_plane_mp_state();
	test_plane_userspace_switch();

	ksft_finished();
}
