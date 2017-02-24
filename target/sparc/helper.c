/*
 *  Misc Sparc helpers
 *
 *  Copyright (c) 2003-2005 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "sysemu/sysemu.h"

void cpu_raise_exception_ra(CPUSPARCState *env, int tt, uintptr_t ra)
{
    CPUState *cs = CPU(sparc_env_get_cpu(env));

    cs->exception_index = tt;
    cpu_loop_exit_restore(cs, ra);
}

void helper_raise_exception(CPUSPARCState *env, int tt)
{
    CPUState *cs = CPU(sparc_env_get_cpu(env));

    cs->exception_index = tt;
    cpu_loop_exit(cs);
}

void helper_debug(CPUSPARCState *env)
{
    CPUState *cs = CPU(sparc_env_get_cpu(env));

    cs->exception_index = EXCP_DEBUG;
    cpu_loop_exit(cs);
}

#ifdef TARGET_SPARC64
void helper_tick_set_count(void *opaque, uint64_t count)
{
#if !defined(CONFIG_USER_ONLY)
    cpu_tick_set_count(opaque, count);
#endif
}

uint64_t helper_tick_get_count(CPUSPARCState *env, void *opaque, int mem_idx)
{
#if !defined(CONFIG_USER_ONLY)
    CPUTimer *timer = opaque;

    if (timer->npt && mem_idx < MMU_KERNEL_IDX) {
        cpu_raise_exception_ra(env, TT_PRIV_INSN, GETPC());
    }

    return cpu_tick_get_count(timer);
#else
    return 0;
#endif
}

void helper_tick_set_limit(void *opaque, uint64_t limit)
{
#if !defined(CONFIG_USER_ONLY)
    cpu_tick_set_limit(opaque, limit);
#endif
}
#endif

static target_ulong do_udiv(CPUSPARCState *env, target_ulong a,
                            target_ulong b, int cc, uintptr_t ra)
{
    int overflow = 0;
    uint64_t x0;
    uint32_t x1;

    x0 = (a & 0xffffffff) | ((int64_t) (env->y) << 32);
    x1 = (b & 0xffffffff);

    if (x1 == 0) {
        cpu_raise_exception_ra(env, TT_DIV_ZERO, ra);
    }

    x0 = x0 / x1;
    if (x0 > UINT32_MAX) {
        x0 = UINT32_MAX;
        overflow = 1;
    }

    if (cc) {
        env->cc_dst = x0;
        env->cc_src2 = overflow;
        env->cc_op = CC_OP_DIV;
    }
    return x0;
}

target_ulong helper_udiv(CPUSPARCState *env, target_ulong a, target_ulong b)
{
    return do_udiv(env, a, b, 0, GETPC());
}

target_ulong helper_udiv_cc(CPUSPARCState *env, target_ulong a, target_ulong b)
{
    return do_udiv(env, a, b, 1, GETPC());
}

static target_ulong do_sdiv(CPUSPARCState *env, target_ulong a,
                            target_ulong b, int cc, uintptr_t ra)
{
    int overflow = 0;
    int64_t x0;
    int32_t x1;

    x0 = (a & 0xffffffff) | ((int64_t) (env->y) << 32);
    x1 = (b & 0xffffffff);

    if (x1 == 0) {
        cpu_raise_exception_ra(env, TT_DIV_ZERO, ra);
    } else if (x1 == -1 && x0 == INT64_MIN) {
        x0 = INT32_MAX;
        overflow = 1;
    } else {
        x0 = x0 / x1;
        if ((int32_t) x0 != x0) {
            x0 = x0 < 0 ? INT32_MIN : INT32_MAX;
            overflow = 1;
        }
    }

    if (cc) {
        env->cc_dst = x0;
        env->cc_src2 = overflow;
        env->cc_op = CC_OP_DIV;
    }
    return x0;
}

target_ulong helper_sdiv(CPUSPARCState *env, target_ulong a, target_ulong b)
{
    return do_sdiv(env, a, b, 0, GETPC());
}

target_ulong helper_sdiv_cc(CPUSPARCState *env, target_ulong a, target_ulong b)
{
    return do_sdiv(env, a, b, 1, GETPC());
}

#ifdef TARGET_SPARC64
int64_t helper_sdivx(CPUSPARCState *env, int64_t a, int64_t b)
{
    if (b == 0) {
        /* Raise divide by zero trap.  */
        cpu_raise_exception_ra(env, TT_DIV_ZERO, GETPC());
    } else if (b == -1) {
        /* Avoid overflow trap with i386 divide insn.  */
        return -a;
    } else {
        return a / b;
    }
}

uint64_t helper_udivx(CPUSPARCState *env, uint64_t a, uint64_t b)
{
    if (b == 0) {
        /* Raise divide by zero trap.  */
        cpu_raise_exception_ra(env, TT_DIV_ZERO, GETPC());
    }
    return a / b;
}
#endif

target_ulong helper_taddcctv(CPUSPARCState *env, target_ulong src1,
                             target_ulong src2)
{
    target_ulong dst;

    /* Tag overflow occurs if either input has bits 0 or 1 set.  */
    if ((src1 | src2) & 3) {
        goto tag_overflow;
    }

    dst = src1 + src2;

    /* Tag overflow occurs if the addition overflows.  */
    if (~(src1 ^ src2) & (src1 ^ dst) & (1u << 31)) {
        goto tag_overflow;
    }

    /* Only modify the CC after any exceptions have been generated.  */
    env->cc_op = CC_OP_TADDTV;
    env->cc_src = src1;
    env->cc_src2 = src2;
    env->cc_dst = dst;
    return dst;

 tag_overflow:
    cpu_raise_exception_ra(env, TT_TOVF, GETPC());
}

target_ulong helper_tsubcctv(CPUSPARCState *env, target_ulong src1,
                             target_ulong src2)
{
    target_ulong dst;

    /* Tag overflow occurs if either input has bits 0 or 1 set.  */
    if ((src1 | src2) & 3) {
        goto tag_overflow;
    }

    dst = src1 - src2;

    /* Tag overflow occurs if the subtraction overflows.  */
    if ((src1 ^ src2) & (src1 ^ dst) & (1u << 31)) {
        goto tag_overflow;
    }

    /* Only modify the CC after any exceptions have been generated.  */
    env->cc_op = CC_OP_TSUBTV;
    env->cc_src = src1;
    env->cc_src2 = src2;
    env->cc_dst = dst;
    return dst;

 tag_overflow:
    cpu_raise_exception_ra(env, TT_TOVF, GETPC());
}

#ifndef TARGET_SPARC64
void helper_power_down(CPUSPARCState *env)
{
    CPUState *cs = CPU(sparc_env_get_cpu(env));

    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    env->pc = env->npc;
    env->npc = env->pc + 4;
    cpu_loop_exit(cs);
}
#endif

#ifdef CONFIG_FULL_TRACE
#define BINARY_TRACE
#define TRACE_BUFFER_SIZE 1
typedef struct trace_entry {
	uint32_t pc;
	uint32_t iword;
	target_ulong data_addr;
} trace_entry;


int32_t trace_head = -1;
trace_entry trace_buffer[TRACE_BUFFER_SIZE];

void trace_flush(uint32_t size);
void trace_flush(uint32_t size) {
	fwrite(trace_buffer, sizeof(trace_entry), size, stderr);
}

void itrace_add(uint32_t pc, uint32_t iword);
void itrace_add(uint32_t pc, uint32_t iword) {
	trace_head++;
	if (trace_head >= TRACE_BUFFER_SIZE) {
		trace_flush(TRACE_BUFFER_SIZE);
		trace_head = 0;
	}
	trace_buffer[trace_head].pc = pc;
	trace_buffer[trace_head].iword = iword;
	trace_buffer[trace_head].data_addr = (target_ulong)-1;
}

void dtrace_add(target_ulong address);
void dtrace_add(target_ulong address) {
	trace_buffer[trace_head].data_addr = address;
}

static int64_t instr_count = 0;
static int64_t traced_instr_count = 0;
static uint32_t prev_pc = 0xFFFFFFFF;
static int64_t skip_first_inst = -1;
static int64_t trace_limit = -1;

void helper_instructiontrace(uint32_t pc, uint32_t iword) {
	// First, we check if skip_first_inst and stop_after_tracing
	// have been initialized from environment variables
	if (skip_first_inst == -1) {
		char *tmp = getenv("QEMU_SKIP_FIRST_INST");
		skip_first_inst = tmp? atoi(tmp): 0;
	}
	if (trace_limit == -1) {
		char *tmp = getenv("QEMU_TRACE_LIMIT");
		trace_limit = tmp? atoi(tmp): 0;
	}

	if (skip_first_inst <= instr_count++) {
		// Do not log an instruction twice. This seems to
		// happen with save and restore instructions
#ifndef BINARY_TRACE
		if (prev_pc != 0xFFFFFFFF && pc != prev_pc) {
			fprintf(stderr, "\n%.8x %.8x", pc, iword);
		}
		else if (prev_pc == 0xFFFFFFFF) {
			fprintf(stderr, "%.8x %.8x", pc, iword);
		}
		prev_pc = pc;
		if (trace_limit > 0 && ++traced_instr_count >= trace_limit) {
			exit(0);
		}
#else
		if (pc != prev_pc) {
			itrace_add(pc, iword);
		}
		prev_pc = pc;
		if (trace_limit > 0 && traced_instr_count++ >= trace_limit) {
			exit(0);
		}
#endif
	}
}

void helper_addresstrace0(target_ulong address) {
	if (skip_first_inst <= instr_count++) {
#ifndef BINARY_TRACE 
#if TARGET_LONG_BITS == 32
		fprintf(stderr, " %.8x ?", address);
#elif TARGET_LONG_BITS == 64
		fprintf(stderr, " %.16lx ?", address);
#endif
#else
		dtrace_add(address);
#endif
	}
}

void helper_addresstrace(target_ulong address, target_ulong data) {
	if (skip_first_inst <= instr_count++) {
#ifndef BINARY_TRACE
#if TARGET_LONG_BITS == 32
		fprintf(stderr, " %.8x %.8x", address, data);
#elif TARGET_LONG_BITS == 64
		fprintf(stderr, " %.16lx %.16lx", address, data);
#endif
#else
		dtrace_add(address);
#endif
	}
}

void helper_addresstrace32(target_ulong address, uint32_t data) {
	if (skip_first_inst <= instr_count++) {
#ifndef BINARY_TRACE
#if TARGET_LONG_BITS == 32
		fprintf(stderr, " %.8x %.8x", address, data);
#elif TARGET_LONG_BITS == 64
		fprintf(stderr, " %.16lx %.8x", address, data);
#endif
#else
		dtrace_add(address);
#endif
	}
}

void helper_addresstrace64(target_ulong address, uint64_t data) {
	if (skip_first_inst <= instr_count++) {
#ifndef BINARY_TRACE
#if TARGET_LONG_BITS == 32
		fprintf(stderr, " %.8x %.16lx", address, data);
#elif TARGET_LONG_BITS == 64
		fprintf(stderr, " %.16lx %.16lx", address, data);
#endif
#else
		dtrace_add(address);
#endif
	}
}
#endif
