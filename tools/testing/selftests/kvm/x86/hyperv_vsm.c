// SPDX-License-Identifier: GPL-2.0
/*
 * Hyper-V Virtual Secure Mode: hypercall exits, XMM payload and plane-aware
 * SynIC and TLB flush handling.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "kvm_util.h"
#include "processor.h"
#include "apic.h"
#include "hyperv.h"
#include "test_util.h"

#define SINT0_VECTOR		0x40
#define SINT0_GSI		24
#define APIC_SPIV		0xF0
#define APIC_IRR		0x200

#define XMM_PATTERN_LO		0x1111111111111111ULL
#define XMM_PATTERN_HI		0x2222222222222222ULL
#define XMM_OUT_LO		0xaaaaaaaaaaaaaaaaULL
#define XMM_OUT_HI		0xbbbbbbbbbbbbbbbbULL
#define VTL_CALL_RAX		0x0123456789abcdefULL
#define IPI_VECTOR		0x60
/* HV_INPUT_VTL: target VTL in bits 3:0, use_target_vtl in bit 4 */
#define HV_INPUT_VTL(vtl)	(BIT(4) | (vtl))

struct hv_tlb_flush {
	u64 address_space;
	u64 flags;
	u64 processor_mask;
} __packed;

static sse128_t make_sse128(u64 lo, u64 hi)
{
	__sse128_u u = { .as_u64 = { lo, hi } };

	return u.vec;
}

static void guest_setup_hypercalls(gpa_t hcall_gpa)
{
	wrmsr(HV_X64_MSR_GUEST_OS_ID, HYPERV_LINUX_OS_ID);
	wrmsr(HV_X64_MSR_HYPERCALL, hcall_gpa);
}

/* Without KVM_CAP_HYPERV_VSM the VSM hypercalls are unknown codes. */
static void guest_cap_off(gpa_t hcall_gpa)
{
	sse128_t xmm[1];
	u64 status;
	u8 vector;

	xmm[0] = make_sse128(XMM_PATTERN_LO, XMM_PATTERN_HI);
	guest_setup_hypercalls(hcall_gpa);

	vector = __hyperv_hypercall(HVCALL_ENABLE_PARTITION_VTL | HV_HYPERCALL_FAST_BIT,
				    0, 0, &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status & 0xffff, HV_STATUS_INVALID_HYPERCALL_CODE);

	hyperv_write_xmm_input(xmm, 1);
	vector = __hyperv_hypercall(HVCALL_GET_VP_REGISTERS | HV_HYPERCALL_FAST_BIT,
				    0, 0, &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status & 0xffff, HV_STATUS_INVALID_HYPERCALL_CODE);

	GUEST_DONE();
}

static void guest_cap_on(gpa_t hcall_gpa, gpa_t input_gpa)
{
	sse128_t xmm[3];
	u64 status, rax;
	u8 vector;

	xmm[0] = make_sse128(XMM_PATTERN_LO, XMM_PATTERN_HI);
	guest_setup_hypercalls(hcall_gpa);

	/* Memory-based call: the input GPA travels in the exit. */
	vector = __hyperv_hypercall(HVCALL_ENABLE_VP_VTL, input_gpa, 0, &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status, HV_STATUS_SUCCESS);
	GUEST_SYNC(1);

	/* Fast call whose input fits the registers: no XMM exit. */
	vector = __hyperv_hypercall(HVCALL_ENABLE_PARTITION_VTL | HV_HYPERCALL_FAST_BIT,
				    XMM_PATTERN_LO, XMM_PATTERN_HI, &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status, HV_STATUS_SUCCESS);
	GUEST_SYNC(2);

	/* Fast call with XMM input and output. */
	hyperv_write_xmm_input(xmm, 1);
	vector = __hyperv_hypercall(HVCALL_GET_VP_REGISTERS | HV_HYPERCALL_FAST_BIT,
				    0, 0, &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status, HV_STATUS_SUCCESS);
	read_sse_reg(2, &xmm[2]);
	GUEST_ASSERT_EQ(sse128_lo(xmm[2]), XMM_OUT_LO);
	GUEST_ASSERT_EQ(sse128_hi(xmm[2]), XMM_OUT_HI);
	GUEST_SYNC(3);

	/* HvCallVtlCall leaves RAX alone. */
	asm volatile("vmcall"
		     : "=a" (rax)
		     : "a" (VTL_CALL_RAX), "c" (HVCALL_VTL_CALL)
		     : "memory", "rdx", "r8", "r9", "r10", "r11");
	GUEST_ASSERT_EQ(rax, VTL_CALL_RAX);
	GUEST_SYNC(4);

	/*
	 * In-kernel cluster IPI with a target VTL (byte 4 of the input, fast
	 * form bits 39:32): the caller's own VTL is allowed, a higher one is
	 * refused.  An empty processor mask keeps the allowed call a no-op.
	 */
	vector = __hyperv_hypercall(HVCALL_SEND_IPI | HV_HYPERCALL_FAST_BIT,
				    IPI_VECTOR | ((u64)HV_INPUT_VTL(0) << 32), 0,
				    &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status & 0xffff, HV_STATUS_SUCCESS);

	vector = __hyperv_hypercall(HVCALL_SEND_IPI | HV_HYPERCALL_FAST_BIT,
				    IPI_VECTOR | ((u64)HV_INPUT_VTL(1) << 32), 0,
				    &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status & 0xffff, HV_STATUS_ACCESS_DENIED);

	GUEST_DONE();
}

static void test_cap_off(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	gva_t hcall_page;

	vm = vm_create_with_one_vcpu(&vcpu, guest_cap_off);
	vcpu_set_hv_cpuid(vcpu);
	hcall_page = vm_alloc_page(vm);
	vcpu_args_set(vcpu, 1, addr_gva2gpa(vm, hcall_page));

	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	case UCALL_DONE:
		break;
	default:
		TEST_FAIL("Unexpected exit %u", vcpu->run->exit_reason);
	}

	kvm_vm_free(vm);
	ksft_test_result_pass("VSM hypercalls refused without the cap\n");
}

static void expect_hcall_exit(struct kvm_vcpu *vcpu, u32 type, u16 code)
{
	struct kvm_hyperv_exit *exit = &vcpu->run->hyperv;

	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_HYPERV);
	TEST_ASSERT_EQ(exit->type, type);
	TEST_ASSERT_EQ(exit->u.hcall.input & 0xffff, code);
}

static void expect_sync(struct kvm_vcpu *vcpu, u64 stage)
{
	struct ucall uc;

	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[1], stage);
}

static void test_cap_on(void)
{
	struct kvm_hyperv_exit *exit;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	gva_t hcall_page, input_page;
	gpa_t input_gpa;

	vm = vm_create_with_one_vcpu(&vcpu, guest_cap_on);
	vm_enable_cap(vm, KVM_CAP_HYPERV_VSM, 0);
	vcpu_set_hv_cpuid(vcpu);
	hcall_page = vm_alloc_page(vm);
	input_page = vm_alloc_page(vm);
	input_gpa = addr_gva2gpa(vm, input_page);
	vcpu_args_set(vcpu, 2, addr_gva2gpa(vm, hcall_page), input_gpa);
	exit = &vcpu->run->hyperv;

	vcpu_run(vcpu);
	expect_hcall_exit(vcpu, KVM_EXIT_HYPERV_HCALL, HVCALL_ENABLE_VP_VTL);
	TEST_ASSERT_EQ(exit->u.hcall.params[0], input_gpa);
	exit->u.hcall.result = HV_STATUS_SUCCESS;
	vcpu_run(vcpu);
	expect_sync(vcpu, 1);

	vcpu_run(vcpu);
	expect_hcall_exit(vcpu, KVM_EXIT_HYPERV_HCALL, HVCALL_ENABLE_PARTITION_VTL);
	TEST_ASSERT_EQ(exit->u.hcall.params[0], XMM_PATTERN_LO);
	TEST_ASSERT_EQ(exit->u.hcall.params[1], XMM_PATTERN_HI);
	exit->u.hcall.result = HV_STATUS_SUCCESS;
	vcpu_run(vcpu);
	expect_sync(vcpu, 2);

	vcpu_run(vcpu);
	expect_hcall_exit(vcpu, KVM_EXIT_HYPERV_HCALL_XMM, HVCALL_GET_VP_REGISTERS);
	TEST_ASSERT_EQ(exit->u.hcall.xmm[0].low, XMM_PATTERN_LO);
	TEST_ASSERT_EQ(exit->u.hcall.xmm[0].high, XMM_PATTERN_HI);
	exit->u.hcall.xmm[2].low = XMM_OUT_LO;
	exit->u.hcall.xmm[2].high = XMM_OUT_HI;
	exit->u.hcall.result = HV_STATUS_SUCCESS;
	vcpu_run(vcpu);
	expect_sync(vcpu, 3);

	vcpu_run(vcpu);
	expect_hcall_exit(vcpu, KVM_EXIT_HYPERV_HCALL, HVCALL_VTL_CALL);
	/* Must not reach the guest's RAX. */
	exit->u.hcall.result = HV_STATUS_INVALID_PARAMETER;
	vcpu_run(vcpu);
	expect_sync(vcpu, 4);

	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	case UCALL_DONE:
		break;
	default:
		TEST_FAIL("Unexpected exit %u", vcpu->run->exit_reason);
	}

	kvm_vm_free(vm);
	ksft_test_result_pass("VSM hypercall exits, XMM payload and IPI target VTL\n");
}

static bool has_irr(struct kvm_lapic_state *apic, int vector)
{
	int bit = (APIC_IRR + (vector >> 5) * 16) * CHAR_BIT + (vector & 31);

	return apic->regs[bit >> 3] & (1 << (bit & 7));
}

static void enable_lapic(struct kvm_lapic_state *apic)
{
	apic->regs[APIC_SPIV + 1] |= 1;
}

#define TSC_PAGE0_GPA		0x200000
#define TSC_PAGE1_GPA		0x201000
#define TSC_PAGE_ENABLE		BIT_ULL(0)

/* The reference TSC page as the guest sees it. */
struct tsc_page {
	u32 tsc_sequence;
	u32 reserved1;
	u64 tsc_scale;
	s64 tsc_offset;
};

static void guest_tsc_page(void)
{
	GUEST_SYNC(1);
	GUEST_DONE();
}

static u32 tsc_page_sequence(struct kvm_vm *vm, gpa_t gpa)
{
	struct tsc_page *page = addr_gpa2hva(vm, gpa);

	return READ_ONCE(page->tsc_sequence);
}

/*
 * A plane that enables its reference TSC page while another plane's page is
 * valid gets the current parameters; the other page stays valid.
 */
/* Runs on plane 1: enables its own reference TSC page, as a guest does. */
static void guest_plane1_tsc_page(void)
{
	wrmsr(HV_X64_MSR_REFERENCE_TSC, TSC_PAGE1_GPA | TSC_PAGE_ENABLE);
	GUEST_SYNC(1);
	GUEST_DONE();
}

static void test_plane_tsc_page(void)
{
	struct kvm_plane_vcpu *plane_vcpu;
	struct tsc_page *page0, *page1;
	struct kvm_plane *plane;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_PLANES_USERSPACE_SWITCH));

	/* planes need the split irqchip */
	kvm_force_split_irqchip = true;
	vm = __vm_create(VM_SHAPE_DEFAULT, 1, 0);
	kvm_force_split_irqchip = false;
	vm_enable_cap(vm, KVM_CAP_PLANES_USERSPACE_SWITCH, 0);
	vcpu = vm_vcpu_add(vm, 0, guest_tsc_page);
	vcpu_set_hv_cpuid(vcpu);
	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	vcpu_sregs_get(vcpu, &sregs);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_SREGS, &sregs);
	vcpu_regs_get(vcpu, &regs);
	regs.rip = (unsigned long)guest_plane1_tsc_page;
	regs.rsp = vm_alloc_stack(vm, DEFAULT_STACK_PGS);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_REGS, &regs);

	page0 = addr_gpa2hva(vm, TSC_PAGE0_GPA);
	page1 = addr_gpa2hva(vm, TSC_PAGE1_GPA);
	memset(page0, 0, sizeof(*page0));
	memset(page1, 0, sizeof(*page1));

	/* Plane 0 enables its page; running the vCPU publishes it. */
	vcpu_set_msr(vcpu, HV_X64_MSR_REFERENCE_TSC,
		     TSC_PAGE0_GPA | TSC_PAGE_ENABLE);
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT(tsc_page_sequence(vm, TSC_PAGE0_GPA),
		    "plane 0's page is valid after the vCPU ran");

	/*
	 * Plane 1 enables its own page while plane 0's is valid.  The guest
	 * write publishes the page before the vCPU runs on.
	 */
	vcpu->run->plane = 1;
	vcpu_run(vcpu);
	expect_sync(vcpu, 1);
	TEST_ASSERT_EQ(vcpu->run->plane, 1);

	TEST_ASSERT(tsc_page_sequence(vm, TSC_PAGE0_GPA),
		    "plane 0's page stays valid");
	TEST_ASSERT(tsc_page_sequence(vm, TSC_PAGE1_GPA),
		    "plane 1's page becomes valid at once");
	TEST_ASSERT_EQ(page0->tsc_scale, page1->tsc_scale);
	TEST_ASSERT_EQ(page0->tsc_offset, page1->tsc_offset);
	TEST_ASSERT_EQ(page0->tsc_sequence, page1->tsc_sequence);

	kvm_vm_free(vm);
	ksft_test_result_pass("Plane 1 TSC page published, plane 0 page stays valid\n");
}

/* A SINT route naming plane 1 interrupts plane 1's SynIC only. */
static void test_plane_synic(void)
{
	struct kvm_irq_routing *routing;
	struct kvm_lapic_state lapic0, lapic1;
	struct kvm_plane_vcpu *plane_vcpu;
	struct kvm_irq_level irq_level = { .irq = SINT0_GSI, .level = 1 };
	struct kvm_enable_cap cap = { .cap = KVM_CAP_HYPERV_SYNIC2 };
	struct kvm_plane *plane;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	vm = vm_create_barebones_irqchip(true);
	vcpu = __vm_vcpu_add(vm, 0);
	vcpu_init_cpuid(vcpu, kvm_get_supported_cpuid());
	vcpu_set_hv_cpuid(vcpu);
	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	vcpu_set_msr(vcpu, MSR_IA32_APICBASE,
		     APIC_DEFAULT_GPA | MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);
	vcpu_ioctl(vcpu, KVM_GET_LAPIC, &lapic0);
	enable_lapic(&lapic0);
	vcpu_ioctl(vcpu, KVM_SET_LAPIC, &lapic0);

	_plane_vcpu_set_msr(plane_vcpu, MSR_IA32_APICBASE,
			    APIC_DEFAULT_GPA | MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_LAPIC, &lapic1);
	enable_lapic(&lapic1);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_LAPIC, &lapic1);

	/* Plane 1's SynIC: activated and SINT0 armed through the plane vCPU fd. */
	plane_vcpu_ioctl(plane_vcpu, KVM_ENABLE_CAP, &cap);
	_plane_vcpu_set_msr(plane_vcpu, HV_X64_MSR_SINT0, SINT0_VECTOR);

	routing = calloc(1, sizeof(*routing) + sizeof(routing->entries[0]));
	TEST_ASSERT(routing, "Failed to allocate routing table");
	routing->nr = 1;
	routing->entries[0].gsi = SINT0_GSI;
	routing->entries[0].type = KVM_IRQ_ROUTING_HV_SINT;
	routing->entries[0].u.hv_sint.vcpu = 0;
	routing->entries[0].u.hv_sint.sint = 0;
	routing->entries[0].u.hv_sint.plane = 1;
	vm_ioctl(vm, KVM_SET_GSI_ROUTING, routing);
	free(routing);

	vm_ioctl(vm, KVM_IRQ_LINE, &irq_level);

	vcpu_ioctl(vcpu, KVM_GET_LAPIC, &lapic0);
	TEST_ASSERT(!has_irr(&lapic0, SINT0_VECTOR), "SINT vector clear in plane 0");
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_LAPIC, &lapic1);
	TEST_ASSERT(has_irr(&lapic1, SINT0_VECTOR), "SINT vector set in plane 1");

	kvm_vm_free(vm);
	ksft_test_result_pass("SINT route on plane 1 lands in plane 1\n");
}

static void guest_plane0(void)
{
	GUEST_SYNC(0);
	GUEST_DONE();
}

/* Runs on plane 1: a flush of all processors targets plane 1 only. */
static void guest_plane1_flush(gpa_t hcall_gpa, gva_t flush_gva, gpa_t flush_gpa)
{
	struct hv_tlb_flush *flush = (struct hv_tlb_flush *)flush_gva;
	u64 status;
	u8 vector;

	guest_setup_hypercalls(hcall_gpa);

	flush->address_space = 0;
	flush->flags = HV_FLUSH_ALL_PROCESSORS;
	flush->processor_mask = 0;
	vector = __hyperv_hypercall(HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE, flush_gpa,
				    0, &status);
	GUEST_ASSERT(!vector);
	GUEST_ASSERT_EQ(status & 0xffff, HV_STATUS_SUCCESS);
	GUEST_SYNC(1);
	GUEST_DONE();
}

/*
 * With the plane 0 vCPU TLB flush inhibited, a flush issued from plane 1
 * must complete: it targets the plane 1 vCPUs, not the inhibited sibling.
 */
static void test_plane_tlb_flush(void)
{
	struct kvm_hyperv_tlb_flush_inhibit inhibit = { .inhibit = 1 };
	struct kvm_plane_vcpu *plane_vcpu;
	struct kvm_plane *plane;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t hcall_page, flush_page;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_PLANES_USERSPACE_SWITCH));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_HYPERV_TLB_FLUSH_INHIBIT));

	kvm_force_split_irqchip = true;
	vm = __vm_create(VM_SHAPE_DEFAULT, 1, 0);
	kvm_force_split_irqchip = false;
	vm_enable_cap(vm, KVM_CAP_PLANES_USERSPACE_SWITCH, 0);

	vcpu = vm_vcpu_add(vm, 0, guest_plane0);
	vcpu_set_hv_cpuid(vcpu);
	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	hcall_page = vm_alloc_page(vm);
	flush_page = vm_alloc_page(vm);

	vcpu_sregs_get(vcpu, &sregs);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_SREGS, &sregs);
	vcpu_regs_get(vcpu, &regs);
	regs.rip = (unsigned long)guest_plane1_flush;
	regs.rsp = vm_alloc_stack(vm, DEFAULT_STACK_PGS);
	regs.rdi = addr_gva2gpa(vm, hcall_page);
	regs.rsi = flush_page;
	regs.rdx = addr_gva2gpa(vm, flush_page);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_REGS, &regs);

	vcpu_ioctl(vcpu, KVM_HYPERV_SET_TLB_FLUSH_INHIBIT, &inhibit);

	vcpu->run->plane = 1;
	vcpu_run(vcpu);
	expect_sync(vcpu, 1);
	TEST_ASSERT_EQ(vcpu->run->plane, 1);

	kvm_vm_free(vm);
	ksft_test_result_pass("TLB flush from plane 1 targets plane 1\n");
}

#define SWITCH_RCX		0x1234ULL

/* Runs on plane 0: the switch target sees the registers userspace wrote. */
static void guest_plane0_switch_target(void)
{
	u64 rcx;

	asm volatile("" : "=c" (rcx));
	GUEST_ASSERT_EQ(rcx, SWITCH_RCX);
	GUEST_SYNC(1);
	GUEST_DONE();
}

/* Runs on plane 1: a VtlReturn leaves RAX as the hypercall page set it. */
static void guest_plane1_vtl_return(gpa_t hcall_gpa)
{
	u64 rax;

	guest_setup_hypercalls(hcall_gpa);
	asm volatile("vmcall"
		     : "=a" (rax)
		     : "a" (VTL_CALL_RAX), "c" (HVCALL_VTL_RETURN)
		     : "memory", "rdx", "r8", "r9", "r10", "r11");
	GUEST_ASSERT_EQ(rax, VTL_CALL_RAX);
	GUEST_SYNC(2);
	GUEST_DONE();
}

static void vtl_switch_vm_create(struct kvm_vm **vmp, struct kvm_vcpu **vcpup,
				 struct kvm_plane_vcpu **plane_vcpup)
{
	struct kvm_plane_vcpu *plane_vcpu;
	struct kvm_plane *plane;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	gva_t hcall_page;

	kvm_force_split_irqchip = true;
	vm = __vm_create(VM_SHAPE_DEFAULT, 1, 0);
	kvm_force_split_irqchip = false;
	vm_enable_cap(vm, KVM_CAP_PLANES_USERSPACE_SWITCH, 0);
	vm_enable_cap(vm, KVM_CAP_HYPERV_VSM, 0);

	vcpu = vm_vcpu_add(vm, 0, guest_plane0_switch_target);
	vcpu_set_hv_cpuid(vcpu);
	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	vcpu_sregs_get(vcpu, &sregs);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_SREGS, &sregs);
	hcall_page = vm_alloc_page(vm);
	vcpu_regs_get(vcpu, &regs);
	regs.rip = (unsigned long)guest_plane1_vtl_return;
	regs.rsp = vm_alloc_stack(vm, DEFAULT_STACK_PGS);
	regs.rdi = addr_gva2gpa(vm, hcall_page);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_REGS, &regs);

	*vmp = vm;
	*vcpup = vcpu;
	*plane_vcpup = plane_vcpu;
}

static void expect_vtl_return_exit(struct kvm_vcpu *vcpu)
{
	vcpu->run->plane = 1;
	vcpu_run(vcpu);
	expect_hcall_exit(vcpu, KVM_EXIT_HYPERV_HCALL, HVCALL_VTL_RETURN);
	TEST_ASSERT_EQ(vcpu->run->plane, 1);
}

/*
 * After a VtlReturn exit the target plane cannot run until KVM_SET_REGS has
 * written it; writing it first makes the same KVM_RUN succeed.
 */
static void test_vtl_switch_order(void)
{
	struct kvm_plane_vcpu *plane_vcpu;
	struct kvm_vcpu *vcpu;
	struct kvm_regs regs;
	struct kvm_vm *vm;
	int r;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_PLANES_USERSPACE_SWITCH));

	vtl_switch_vm_create(&vm, &vcpu, &plane_vcpu);
	expect_vtl_return_exit(vcpu);

	vcpu->run->plane = 0;
	r = __vcpu_run(vcpu);
	TEST_ASSERT(r == -1 && errno == EINVAL,
		    "Target ran before its registers were written. ret: %d, errno: %d",
		    r, errno);

	vcpu_regs_get(vcpu, &regs);
	regs.rcx = SWITCH_RCX;
	vcpu_regs_set(vcpu, &regs);
	vcpu->run->plane = 0;
	vcpu_run(vcpu);
	expect_sync(vcpu, 1);
	TEST_ASSERT_EQ(vcpu->run->plane, 0);

	kvm_vm_free(vm);
	ksft_test_result_pass("VtlReturn target refused until KVM_SET_REGS\n");
}

/*
 * The VtlReturn exit carries no result: the exiting plane keeps RAX as the
 * hypercall page set it, and the registers written to the target before its
 * KVM_RUN are what its first instruction reads.
 */
static void test_vtl_switch_registers(void)
{
	struct kvm_plane_vcpu *plane_vcpu;
	struct kvm_vcpu *vcpu;
	struct kvm_regs regs;
	struct kvm_vm *vm;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_PLANES_USERSPACE_SWITCH));

	vtl_switch_vm_create(&vm, &vcpu, &plane_vcpu);
	expect_vtl_return_exit(vcpu);

	/* The exit does not reach RAX: the exiting plane still holds it. */
	plane_vcpu_ioctl(plane_vcpu, KVM_GET_REGS, &regs);
	TEST_ASSERT_EQ(regs.rax, VTL_CALL_RAX);

	vcpu_regs_get(vcpu, &regs);
	regs.rcx = SWITCH_RCX;
	vcpu_regs_set(vcpu, &regs);
	vcpu->run->plane = 0;
	vcpu_run(vcpu);
	expect_sync(vcpu, 1);

	/* Back on plane 1 the hypercall completes with RAX untouched. */
	vcpu->run->plane = 1;
	vcpu_run(vcpu);
	expect_sync(vcpu, 2);
	TEST_ASSERT_EQ(vcpu->run->plane, 1);

	kvm_vm_free(vm);
	ksft_test_result_pass("VtlReturn keeps RAX, target reads the written registers\n");
}

#define AUTO_EOI_VECTOR		0x40
#define AUTO_EOI_SPINS		BIT_ULL(28)
#define EOI_MSR_VECTOR		0x60
#define EOI_MSR_RESERVED	0xdeadbeef00000000ULL
#define APICV_INHIBIT_REASON_HYPERV	1

#define TRACEFS		"/sys/kernel/tracing"
#define INHIBIT_EVENT	TRACEFS "/events/kvm/kvm_apicv_inhibit_changed/enable"

static u32 auto_eoi_count;

static bool write_tracefs(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY);
	bool ok;

	if (fd < 0)
		return false;
	ok = write(fd, val, strlen(val)) == (ssize_t)strlen(val);
	close(fd);
	return ok;
}

/* Arm the inhibit tracepoint; false when tracefs is not usable here. */
static bool inhibit_trace_start(void)
{
	return write_tracefs(TRACEFS "/trace", "") &&
	       write_tracefs(INHIBIT_EVENT, "1") &&
	       write_tracefs(TRACEFS "/tracing_on", "1");
}

/* True when the trace holds a "set" event for the given reason. */
static bool inhibit_trace_has_set(int reason)
{
	char line[256], needle[32];
	bool found = false;
	FILE *f;

	write_tracefs(INHIBIT_EVENT, "0");
	f = fopen(TRACEFS "/trace", "r");
	if (!f)
		return false;
	snprintf(needle, sizeof(needle), "set reason=%d,", reason);
	while (fgets(line, sizeof(line), f))
		if (strstr(line, "kvm_apicv_inhibit_changed:") && strstr(line, needle))
			found = true;
	fclose(f);
	return found;
}

/* Never writes EOI, as a guest relying on auto-EOI does. */
static void guest_auto_eoi_handler(struct ex_regs *regs)
{
	WRITE_ONCE(auto_eoi_count, auto_eoi_count + 1);
}

static void guest_wait_auto_eoi(u32 count)
{
	u64 spins = 0;

	while (READ_ONCE(auto_eoi_count) < count) {
		GUEST_ASSERT(spins++ < AUTO_EOI_SPINS);
		sti_nop_cli();
	}
}

static u64 guest_apic_vector_bit(u32 reg, u8 vector)
{
	return x2apic_read_reg(reg + (vector / 32) * 0x10) & BIT(vector % 32);
}

/* Runs on plane 1 and takes the marked vector twice without any EOI. */
static void guest_plane1_auto_eoi(void)
{
	x2apic_enable();
	GUEST_SYNC(1);

	guest_wait_auto_eoi(1);
	GUEST_ASSERT(!guest_apic_vector_bit(APIC_ISR, AUTO_EOI_VECTOR));
	GUEST_ASSERT(!guest_apic_vector_bit(APIC_IRR, AUTO_EOI_VECTOR));
	GUEST_ASSERT_EQ(x2apic_read_reg(APIC_PROCPRI), 0);
	GUEST_SYNC(2);

	guest_wait_auto_eoi(2);
	GUEST_ASSERT(!guest_apic_vector_bit(APIC_ISR, AUTO_EOI_VECTOR));
	GUEST_ASSERT(!guest_apic_vector_bit(APIC_IRR, AUTO_EOI_VECTOR));
	GUEST_SYNC(3);
	GUEST_DONE();
}

/*
 * A vector marked auto-EOI on the plane 1 vCPU and signalled on the plane 1
 * fd is taken by plane 1, twice without an EOI in between, and never shows
 * in the ISR or IRR.
 */
static void test_plane_auto_eoi(void)
{
	struct kvm_hyperv_auto_eoi mark = {
		.vector = AUTO_EOI_VECTOR,
		.set = KVM_HYPERV_AUTO_EOI_SET,
	};
	struct kvm_msi msi = {
		.address_lo = APIC_DEFAULT_GPA,
		.data = AUTO_EOI_VECTOR,
	};
	struct kvm_plane_vcpu *plane_vcpu;
	struct kvm_plane *plane;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	bool traced;
	int r;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_PLANES_USERSPACE_SWITCH));

	kvm_force_split_irqchip = true;
	vm = __vm_create(VM_SHAPE_DEFAULT, 1, 0);
	kvm_force_split_irqchip = false;
	vm_enable_cap(vm, KVM_CAP_PLANES_USERSPACE_SWITCH, 0);
	vm_enable_cap(vm, KVM_CAP_HYPERV_VSM, 0);

	vcpu = vm_vcpu_add(vm, 0, guest_plane0);
	vcpu_set_hv_cpuid(vcpu);
	vm_install_exception_handler(vm, AUTO_EOI_VECTOR, guest_auto_eoi_handler);
	plane = vm_plane_add(vm, 1);
	plane_vcpu = __vm_plane_vcpu_add(vcpu, plane);

	_plane_vcpu_set_msr(plane_vcpu, MSR_IA32_APICBASE,
			    APIC_DEFAULT_GPA | MSR_IA32_APICBASE_ENABLE | X2APIC_ENABLE);

	vcpu_sregs_get(vcpu, &sregs);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_SREGS, &sregs);
	vcpu_regs_get(vcpu, &regs);
	regs.rip = (unsigned long)guest_plane1_auto_eoi;
	regs.rsp = vm_alloc_stack(vm, DEFAULT_STACK_PGS);
	plane_vcpu_ioctl(plane_vcpu, KVM_SET_REGS, &regs);

	/* The mark inhibits APICv on this vCPU only, never VM-wide. */
	traced = inhibit_trace_start();
	plane_vcpu_ioctl(plane_vcpu, KVM_HYPERV_SET_AUTO_EOI, &mark);

	vcpu->run->plane = 1;
	vcpu_run(vcpu);
	expect_sync(vcpu, 1);
	TEST_ASSERT_EQ(vcpu->run->plane, 1);

	r = __plane_ioctl(plane, KVM_SIGNAL_MSI, &msi);
	TEST_ASSERT(r == 1, "MSI to plane 1. ret: %d, errno: %d", r, errno);
	vcpu_run(vcpu);
	expect_sync(vcpu, 2);
	TEST_ASSERT_EQ(vcpu->run->plane, 1);

	r = __plane_ioctl(plane, KVM_SIGNAL_MSI, &msi);
	TEST_ASSERT(r == 1, "Second MSI to plane 1. ret: %d, errno: %d", r, errno);
	vcpu_run(vcpu);
	expect_sync(vcpu, 3);
	TEST_ASSERT_EQ(vcpu->run->plane, 1);

	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	case UCALL_DONE:
		break;
	default:
		TEST_FAIL("Unexpected exit %u", vcpu->run->exit_reason);
	}

	if (traced)
		TEST_ASSERT(!inhibit_trace_has_set(APICV_INHIBIT_REASON_HYPERV),
			    "Auto-EOI mark inhibited APICv VM-wide (reason HYPERV)");

	kvm_vm_free(vm);
	ksft_test_result_pass("Auto-EOI vector delivered to plane 1 without ISR\n");
	if (traced)
		ksft_test_result_pass("Auto-EOI mark does not inhibit APICv VM-wide\n");
	else
		ksft_test_result_skip("Auto-EOI mark does not inhibit APICv VM-wide: no tracefs\n");
}

/*
 * Hyper-V performs an EOI for any write to HV_X64_MSR_EOI and ignores bits
 * 63:32 of the value.  Take an interrupt without acknowledging it, then write
 * the MSR with those bits set: no fault, and the ISR bit is gone.
 */
static void guest_eoi_msr_reserved_bits(void)
{
	u8 vector;

	x2apic_enable();
	x2apic_write_reg(APIC_SELF_IPI, EOI_MSR_VECTOR);
	guest_wait_auto_eoi(1);
	GUEST_ASSERT(guest_apic_vector_bit(APIC_ISR, EOI_MSR_VECTOR));

	vector = wrmsr_safe(HV_X64_MSR_EOI, EOI_MSR_RESERVED | EOI_MSR_VECTOR);
	GUEST_ASSERT_EQ(vector, 0);
	GUEST_ASSERT(!guest_apic_vector_bit(APIC_ISR, EOI_MSR_VECTOR));
	GUEST_DONE();
}

static void test_eoi_msr_reserved_bits(void)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;

	vm = vm_create_with_one_vcpu(&vcpu, guest_eoi_msr_reserved_bits);
	vcpu_set_hv_cpuid(vcpu);
	vm_install_exception_handler(vm, EOI_MSR_VECTOR, guest_auto_eoi_handler);

	vcpu_run(vcpu);
	switch (get_ucall(vcpu, &uc)) {
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
	case UCALL_DONE:
		break;
	default:
		TEST_FAIL("Unexpected exit %u", vcpu->run->exit_reason);
	}

	kvm_vm_free(vm);
	ksft_test_result_pass("HV_X64_MSR_EOI ignores reserved bits\n");
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm;
	int cap_planes;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_HYPERV_VSM));

	ksft_print_header();
	ksft_set_plan(10);

	test_cap_off();
	test_cap_on();
	test_eoi_msr_reserved_bits();

	vm = vm_create_barebones_irqchip(true);
	cap_planes = vm_check_cap(vm, KVM_CAP_PLANES);
	kvm_vm_free(vm);
	if (cap_planes > 1) {
		test_plane_synic();
		test_plane_tsc_page();
		test_plane_tlb_flush();
		test_vtl_switch_order();
		test_vtl_switch_registers();
		test_plane_auto_eoi();
	} else {
		ksft_test_result_skip("SINT route on plane 1 lands in plane 1\n");
		ksft_test_result_skip("Plane 1 TSC page published, plane 0 page stays valid\n");
		ksft_test_result_skip("TLB flush from plane 1 targets plane 1\n");
		ksft_test_result_skip("VtlReturn target refused until KVM_SET_REGS\n");
		ksft_test_result_skip("VtlReturn keeps RAX, target reads the written registers\n");
		ksft_test_result_skip("Auto-EOI vector delivered to plane 1 without ISR\n");
		ksft_test_result_skip("Auto-EOI mark does not inhibit APICv VM-wide\n");
	}

	ksft_finished();
}
