// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Red Hat, Inc.
 *
 * Test for architecture-neutral VM plane functionality
 */
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_util.h"

#include "kvm_util.h"
#include "ucall_common.h"
#include "asm/kvm.h"
#include "linux/kvm.h"

void test_create_plane_errors(int max_planes)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	int planefd, plane_vcpufd;

	/* Planes require an in-kernel (split) IRQ chip. */
	vm = vm_create_barebones_irqchip(true);
	vcpu = __vm_vcpu_add(vm, 0);

	planefd = __vm_ioctl(vm, KVM_CREATE_PLANE, (void *)(unsigned long)0);
	TEST_ASSERT(planefd == -1 && errno == EEXIST,
		    "Creating existing plane, expecting EEXIST. ret: %d, errno: %d",
		    planefd, errno);

	planefd = __vm_ioctl(vm, KVM_CREATE_PLANE, (void *)(unsigned long)max_planes);
	TEST_ASSERT(planefd == -1 && errno == EINVAL,
		    "Creating plane %d, expecting EINVAL. ret: %d, errno: %d",
		    max_planes, planefd, errno);

	plane_vcpufd = __vm_ioctl(vm, KVM_CREATE_VCPU, (void *)(unsigned long)vcpu->id);
	TEST_ASSERT(plane_vcpufd == -1 && errno == EEXIST,
		    "Creating existing vCPU for plane 0, expecting EEXIST. ret: %d, errno: %d",
		    plane_vcpufd, errno);

	kvm_vm_free(vm);
	ksft_test_result_pass("error conditions\n");
}

void test_create_plane(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_plane *plane;
	int r;

	vm = vm_create_barebones_irqchip(true);
	vcpu = __vm_vcpu_add(vm, 0);

	plane = vm_plane_add(vm, 1);

	/* A plane fd takes plane ioctls only; capabilities are a VM matter. */
	r = __plane_ioctl(plane, KVM_CHECK_EXTENSION, (void *)(unsigned long)KVM_CAP_PLANES);
	TEST_ASSERT(r == -1 && errno == ENOTTY,
		    "KVM_CHECK_EXTENSION on a plane fd, expecting ENOTTY. ret: %d, errno: %d",
		    r, errno);

	r = __vm_ioctl(vm, KVM_CREATE_PLANE, (void *)(unsigned long)1);
	TEST_ASSERT(r == -1 && errno == EEXIST,
		    "Creating existing plane, expecting EEXIST. ret: %d, errno: %d",
		    r, errno);

	__vm_plane_vcpu_add(vcpu, plane);

	r = __plane_ioctl(plane, KVM_CREATE_VCPU, (void *)(unsigned long)vcpu->id);
	TEST_ASSERT(r == -1 && errno == EEXIST,
		    "Creating vCPU again for plane 1. ret: %d, errno: %d",
		    r, errno);

	r = __plane_ioctl(plane, KVM_RUN, (void *)(unsigned long)0);
	TEST_ASSERT(r == -1 && errno == ENOTTY,
		    "Running plane vCPU again for plane 1. ret: %d, errno: %d",
		    r, errno);

	kvm_vm_free(vm);
	ksft_test_result_pass("basic planefd and plane_vcpufd operation\n");
}

struct foreign_ioctl {
	struct kvm_vcpu *vcpu;
	struct kvm_plane_vcpu *plane_vcpu;
	int ret_vcpu, err_vcpu, ret_plane, err_plane;
};

static void *foreign_ioctl_thread(void *arg)
{
	struct foreign_ioctl *f = arg;
	struct kvm_regs regs;

	f->ret_vcpu = __vcpu_ioctl(f->vcpu, KVM_GET_REGS, &regs);
	f->err_vcpu = errno;
	f->ret_plane = __plane_vcpu_ioctl(f->plane_vcpu, KVM_GET_REGS, &regs);
	f->err_plane = errno;
	return NULL;
}

static void guest_sync_once(void)
{
	GUEST_SYNC(0);
	GUEST_DONE();
}

/*
 * The planes of a VP are driven by one thread.  Any thread may configure
 * them before the first KVM_RUN; afterwards another thread gets EBUSY.
 */
void test_foreign_thread_ioctl(void)
{
	struct foreign_ioctl f;
	struct kvm_regs regs;
	pthread_t thread;
	struct kvm_vm *vm;

	kvm_force_split_irqchip = true;
	vm = vm_create_with_one_vcpu(&f.vcpu, guest_sync_once);
	kvm_force_split_irqchip = false;
	f.plane_vcpu = __vm_plane_vcpu_add(f.vcpu, vm_plane_add(vm, 1));

	kvm_pthread_create(&thread, NULL, foreign_ioctl_thread, &f);
	pthread_join(thread, NULL);
	TEST_ASSERT(!f.ret_vcpu && !f.ret_plane,
		    "ioctls before KVM_RUN from another thread: %d/%d (errno %d/%d)",
		    f.ret_vcpu, f.ret_plane, f.err_vcpu, f.err_plane);

	vcpu_run(f.vcpu);

	kvm_pthread_create(&thread, NULL, foreign_ioctl_thread, &f);
	pthread_join(thread, NULL);
	TEST_ASSERT(f.ret_vcpu == -1 && f.err_vcpu == EBUSY,
		    "vcpu ioctl from another thread after KVM_RUN: ret %d errno %d",
		    f.ret_vcpu, f.err_vcpu);
	TEST_ASSERT(f.ret_plane == -1 && f.err_plane == EBUSY,
		    "plane vcpu ioctl from another thread after KVM_RUN: ret %d errno %d",
		    f.ret_plane, f.err_plane);

	/* The owning thread keeps going. */
	vcpu_ioctl(f.vcpu, KVM_GET_REGS, &regs);
	plane_vcpu_ioctl(f.plane_vcpu, KVM_GET_REGS, &regs);

	kvm_vm_free(vm);
	ksft_test_result_pass("vcpu ioctls refused from a foreign thread\n");
}

int main(int argc, char *argv[])
{
	struct kvm_vm *vm = vm_create_barebones_irqchip(true);
	int cap_planes = vm_check_cap(vm, KVM_CAP_PLANES);

	kvm_vm_free(vm);
	TEST_REQUIRE(cap_planes);

	ksft_print_header();
	ksft_set_plan(3);

	pr_info("# KVM_CAP_PLANES: %d\n", cap_planes);

	test_create_plane_errors(cap_planes);

	if (cap_planes > 1) {
		test_create_plane();
		test_foreign_thread_ioctl();
	} else {
		ksft_test_result_skip("plane creation requires KVM_CAP_PLANES > 1\n");
		ksft_test_result_skip("vcpu ioctls refused from a foreign thread\n");
	}

	ksft_finished();
}
