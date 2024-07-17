// SPDX-License-Identifier: GPL-2.0
/*
 * Test for x86 KVM_TRANSLATE2
 *
 * Copyright © 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/bitmap.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

/*
 * The PTE_*_MASK macros take the VM's MMU since the x86 selftest MMU rework.
 * Every function below gets @vm, so resolve them against it.
 */
#define PTE_PRESENT_MASK_	PTE_PRESENT_MASK(&vm->mmu)
#define PTE_WRITABLE_MASK_	PTE_WRITABLE_MASK(&vm->mmu)
#define PTE_USER_MASK_		PTE_USER_MASK(&vm->mmu)
#define PTE_ACCESSED_MASK_	PTE_ACCESSED_MASK(&vm->mmu)
#define PTE_DIRTY_MASK_		PTE_DIRTY_MASK(&vm->mmu)
#define PTE_NX_MASK_		PTE_NX_MASK(&vm->mmu)

/* Top level of the guest page tables; the host may give the VM 5 levels. */
#define TOP_LEVEL		(vm->mmu.pgtable_levels)

#define CHECK_ACCESSED_BIT(pte, set, start)                                     \
	({                                                                      \
		for (int _i = start; _i <= TOP_LEVEL; _i++) {                   \
			if (set)                                                \
				TEST_ASSERT(                                    \
					(*pte[_i] & PTE_ACCESSED_MASK_) != 0,    \
					"Page not marked accessed on level %i", \
					_i);                                    \
			else                                                    \
				TEST_ASSERT(                                    \
					(*pte[_i] & PTE_ACCESSED_MASK_) == 0,    \
					"Page marked accessed on level %i",     \
					_i);                                    \
		}                                                               \
	})

#define CHECK_DIRTY_BIT(pte, set)                                              \
	({                                                                     \
		if (set)                                                       \
			TEST_ASSERT((*pte[PG_LEVEL_4K] & PTE_DIRTY_MASK_) != 0, \
				    "Page not marked dirty");                  \
		else                                                           \
			TEST_ASSERT((*pte[PG_LEVEL_4K] & PTE_DIRTY_MASK_) == 0, \
				    "Page marked dirty");                      \
	})

enum point_of_failure {
	pof_none,
	pof_ioctl,
	pof_page_walk,
	pof_no_failure,
};

static struct kvm_translation2 kvm_translate2(struct kvm_vcpu *vcpu,
					      uint64_t vaddr,
					      int flags, int access,
					      enum point_of_failure pof)
{
	struct kvm_translation2 tr = { .linear_address = vaddr,
				       .flags = flags,
				       .access = access };

	int res = ioctl(vcpu->fd, KVM_TRANSLATE2, &tr);

	if (pof == pof_none) {
		/* Any walk result is fine, but the ioctl itself must work. */
		TEST_ASSERT(res == 0, "ioctl failed: ret %d, errno %d",
			    res, errno);
		return tr;
	}

	if (pof == pof_ioctl) {
		TEST_ASSERT(res == -1 && errno == EINVAL,
			    "ioctl didn't fail with EINVAL: ret %d, errno %d",
			    res, errno);
		return tr;
	}

	TEST_ASSERT(res != -1, "ioctl failed");
	TEST_ASSERT((pof != pof_page_walk) == tr.valid,
		    "Page walk fail with code %u", tr.error_code);

	return tr;
}

static void test_translate(struct kvm_vm *vm, struct kvm_vcpu *vcpu, int index,
		    uint64_t *pte[(PG_LEVEL_256T + 1)], gva_t vaddr)
{
	struct kvm_translation2 translation;
	int access = index;

	printf("%s - write: %u, user: %u, exec: %u ...\t",
	       __func__,
	       (access & KVM_TRANSLATE_ACCESS_WRITE) >> 0,
	       (access & KVM_TRANSLATE_ACCESS_USER) >> 1,
	       (access & KVM_TRANSLATE_ACCESS_EXEC) >> 2);

	uint64_t mask = PTE_WRITABLE_MASK_ | PTE_USER_MASK_ | PTE_NX_MASK_;
	uint64_t new_value = 0;

	if (access & KVM_TRANSLATE_ACCESS_WRITE)
		new_value |= PTE_WRITABLE_MASK_;
	if (access & KVM_TRANSLATE_ACCESS_USER)
		new_value |= PTE_USER_MASK_;
	if (!(access & KVM_TRANSLATE_ACCESS_EXEC))
		new_value |= PTE_NX_MASK_;

	for (int i = PG_LEVEL_4K; i <= TOP_LEVEL; i++)
		*pte[i] = (*pte[i] & ~mask) | new_value;

	translation = kvm_translate2(vcpu, vaddr, 0, access, pof_no_failure);

	TEST_ASSERT_EQ(*pte[PG_LEVEL_4K] & GENMASK(51, 12),
		       translation.physical_address);

	/* Check configurations that have extra access requirements */
	for (int i = 0; i < 8; i++) {
		int case_access = i;

		if ((case_access | access) <= access)
			continue;

		translation = kvm_translate2(vcpu, vaddr, 0, case_access,
					     pof_page_walk);
		TEST_ASSERT_EQ(translation.error_code,
			       KVM_TRANSLATE_FAULT_PRIVILEGE_VIOLATION);
	}

	/* Clear accessed bits */
	for (int i = PG_LEVEL_4K; i <= TOP_LEVEL; i++)
		*pte[i] &= ~PTE_ACCESSED_MASK_;

	printf("[ok]\n");
}

static void test_set_bits(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		   uint64_t *pte[(PG_LEVEL_256T + 1)], gva_t vaddr)
{
	printf("%s ...\t", __func__);

	/* Sanity checks */
	CHECK_ACCESSED_BIT(pte, false, PG_LEVEL_4K);
	CHECK_DIRTY_BIT(pte, false);

	kvm_translate2(vcpu, vaddr, 0, 0, pof_no_failure);

	CHECK_ACCESSED_BIT(pte, false, PG_LEVEL_4K);
	CHECK_DIRTY_BIT(pte, false);

	kvm_translate2(vcpu, vaddr, KVM_TRANSLATE_FLAGS_SET_ACCESSED, 0,
		       pof_no_failure);

	CHECK_ACCESSED_BIT(pte, true, PG_LEVEL_4K);
	CHECK_DIRTY_BIT(pte, false);

	kvm_translate2(vcpu, vaddr,
		       KVM_TRANSLATE_FLAGS_SET_ACCESSED | KVM_TRANSLATE_FLAGS_SET_DIRTY,
		       KVM_TRANSLATE_ACCESS_WRITE, pof_no_failure);

	CHECK_ACCESSED_BIT(pte, true, PG_LEVEL_4K);
	CHECK_DIRTY_BIT(pte, true);

	printf("[ok]\n");
}

static void test_errors(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
		 uint64_t *pte[(PG_LEVEL_256T + 1)], gva_t vaddr)
{
	struct kvm_translation2 tr;

	printf("%s ...\t", __func__);

	/* Set an unsupported access bit */
	kvm_translate2(vcpu, vaddr, 0, (1 << 3), pof_ioctl);
	kvm_translate2(vcpu, vaddr, KVM_TRANSLATE_FLAGS_SET_DIRTY, 0, pof_ioctl);
	kvm_translate2(vcpu, vaddr, KVM_TRANSLATE_FLAGS_FORCE_SET_ACCESSED, 0,
		       pof_ioctl);

	/* Try to translate a non-canonical address */
	tr = kvm_translate2(vcpu, 0b101ull << 60, 0, 0, pof_page_walk);
	TEST_ASSERT_EQ(tr.error_code, KVM_TRANSLATE_FAULT_INVALID_GVA);

	uint64_t old_pte = *pte[PG_LEVEL_2M];

	/*
	 * Set a reserved bit: bits 20:13 of a 2M page entry are reserved
	 * whatever the guest's MAXPHYADDR is.
	 */
	*pte[PG_LEVEL_2M] |= PTE_HUGE_MASK(&vm->mmu) | (1ull << 13);

	tr = kvm_translate2(vcpu, vaddr, 0, 0, pof_page_walk);
	TEST_ASSERT_EQ(tr.error_code, KVM_TRANSLATE_FAULT_RESERVED_BITS);

	*pte[PG_LEVEL_2M] = old_pte;

	/* Create a GPA that's definitely not mapped */
	*pte[PG_LEVEL_2M] |= GENMASK(35, 13);

	tr = kvm_translate2(vcpu, vaddr, 0, 0, pof_page_walk);
	TEST_ASSERT_EQ(tr.error_code, KVM_TRANSLATE_FAULT_INVALID_GPA);

	*pte[PG_LEVEL_2M] = old_pte;

	/* Clear accessed bits */
	for (int i = PG_LEVEL_4K; i <= TOP_LEVEL; i++)
		*pte[i] &= ~PTE_ACCESSED_MASK_;

	/* Try translating a non-present page */
	*pte[PG_LEVEL_4K] &= ~PTE_PRESENT_MASK_;

	tr = kvm_translate2(
		vcpu, vaddr,
		KVM_TRANSLATE_FLAGS_SET_ACCESSED |
			KVM_TRANSLATE_FLAGS_FORCE_SET_ACCESSED, 0,
		pof_page_walk);
	TEST_ASSERT_EQ(tr.error_code, KVM_TRANSLATE_FAULT_NOT_PRESENT);
	CHECK_ACCESSED_BIT(pte, true, PG_LEVEL_2M);

	*pte[PG_LEVEL_4K] |= PTE_PRESENT_MASK_;

	/*
	 * Try setting accessed/dirty bits on a PTE that is in read-only memory
	 */
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_ANONYMOUS, 0x80000000, 1, 4,
				    KVM_MEM_READONLY);

	uint64_t *addr = addr_gpa2hva(vm, 0x80000000);
	uint64_t *base = addr_gpa2hva(vm, *pte[PG_LEVEL_2M] & GENMASK(51, 12));

	/* Copy the entire page table */
	for (int i = 0; i < 0x200; i += 1)
		addr[i] = (base[i] & ~PTE_ACCESSED_MASK_) | PTE_PRESENT_MASK_;

	uint64_t old_2m = *pte[PG_LEVEL_2M];
	*pte[PG_LEVEL_2M] &= ~GENMASK(51, 12);
	*pte[PG_LEVEL_2M] |= 0x80000000;

	tr = kvm_translate2(vcpu, vaddr,
			    KVM_TRANSLATE_FLAGS_SET_ACCESSED |
				    KVM_TRANSLATE_FLAGS_SET_DIRTY |
				    KVM_TRANSLATE_FLAGS_FORCE_SET_ACCESSED,
			    KVM_TRANSLATE_ACCESS_WRITE, pof_no_failure);

	TEST_ASSERT(!tr.set_bits_succeeded, "Page not read-only");

	*pte[PG_LEVEL_2M] = old_2m;

	printf("[ok]\n");
}

/* random() yields 31 bits; cover all 64, including the NX bit. */
static uint64_t random_u64(void)
{
	return ((uint64_t)random() << 62) ^ ((uint64_t)random() << 31) ^
	       random();
}

/* Test page walker stability, by trying to translate with garbage PTEs */
static void test_fuzz(struct kvm_vm *vm, struct kvm_vcpu *vcpu,
	       uint64_t *pte[(PG_LEVEL_256T + 1)], gva_t vaddr)
{
	printf("%s ...\t", __func__);

	/*
	 * SET_DIRTY requires write access or the ioctl gate rejects the
	 * call with EINVAL before the walker ever sees the garbage.
	 */
	int fuzz_access = KVM_TRANSLATE_ACCESS_WRITE;

	/* Test gPTEs that point to random addresses */
	for (int level = PG_LEVEL_4K; level <= TOP_LEVEL; level++) {
		for (int i = 0; i < 10000; i++) {
			uint64_t random_address = (random() & GENMASK(29, 0)) << 12;
			*pte[level] = (*pte[level] & ~GENMASK(51, 12)) | random_address;

			kvm_translate2(vcpu, vaddr,
				       KVM_TRANSLATE_FLAGS_SET_ACCESSED |
					       KVM_TRANSLATE_FLAGS_SET_DIRTY |
					       KVM_TRANSLATE_FLAGS_FORCE_SET_ACCESSED,
				       fuzz_access, pof_none);
		}
	}

	/* Test gPTEs with completely random values */
	for (int level = PG_LEVEL_4K; level <= TOP_LEVEL; level++) {
		for (int i = 0; i < 10000; i++) {
			*pte[level] = random_u64();

			kvm_translate2(vcpu, vaddr,
				       KVM_TRANSLATE_FLAGS_SET_ACCESSED |
					       KVM_TRANSLATE_FLAGS_SET_DIRTY |
					       KVM_TRANSLATE_FLAGS_FORCE_SET_ACCESSED,
				       fuzz_access, pof_none);
		}
	}

	printf("[ok]\n");
}

int main(int argc, char *argv[])
{
	uint64_t *pte[(PG_LEVEL_256T + 1)];
	struct kvm_vcpu *vcpu;
	struct kvm_sregs regs;
	struct kvm_vm *vm;
	gva_t vaddr;
	int page_level;

	TEST_REQUIRE(kvm_has_cap(KVM_CAP_TRANSLATE2));

	vm = vm_create_with_one_vcpu(&vcpu, NULL);

	vaddr = __vm_alloc_page(vm, MEM_REGION_TEST_DATA);

	for (page_level = TOP_LEVEL; page_level > PG_LEVEL_NONE;
	     page_level--) {
		pte[page_level] = vm_get_pte_level(vm, vaddr, &page_level);
	}

	/* Enable WP bit in cr0, so kernel accesses uphold write protection */
	vcpu_ioctl(vcpu, KVM_GET_SREGS, &regs);
	regs.cr0 |= X86_CR0_WP;
	vcpu_ioctl(vcpu, KVM_SET_SREGS, &regs);

	for (int index = 0; index < 8; index++)
		test_translate(vm, vcpu, index, pte, vaddr);

	test_set_bits(vm, vcpu, pte, vaddr);
	test_errors(vm, vcpu, pte, vaddr);
	test_fuzz(vm, vcpu, pte, vaddr);

	kvm_vm_free(vm);

	return 0;
}
