#include <linux/bpf.h>
#include <linux/types.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
static void *(*map_lookup)(void *, const void *) = (void *) BPF_FUNC_map_lookup_elem;
static long (*map_update)(void *, const void *, const void *, __u64) = (void *) BPF_FUNC_map_update_elem;
static long (*map_delete)(void *, const void *) = (void *) BPF_FUNC_map_delete_elem;
static __u64 (*pid_tgid)(void) = (void *) BPF_FUNC_get_current_pid_tgid;
static __u64 (*cgroup_id)(void) = (void *) BPF_FUNC_get_current_cgroup_id;
static long (*read_user)(void *, __u32, const void *) = (void *) BPF_FUNC_probe_read_user;
static long (*get_comm)(void *, __u32) = (void *) BPF_FUNC_get_current_comm;
static void *(*ring_reserve)(void *, __u64, __u64) = (void *) BPF_FUNC_ringbuf_reserve;
static void (*ring_submit)(void *, __u64) = (void *) BPF_FUNC_ringbuf_submit;

struct enter { __u64 pad; __s64 id; __u64 args[6]; };
struct leave { __u64 pad; __s64 id; __s64 ret; };
struct event { __u64 cgroup; __s64 result; __u32 pid; __u16 family; __u16 port; __u8 address[16]; char comm[16]; __u32 kind; __u32 padding; };
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384); __type(key, __u64); __type(value, struct event); } pending SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 8 * 1024 * 1024); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, __u64); } dropped SEC(".maps");
static __always_inline int begin(__u64 pointer, __u32 kind) {
  __u8 addr[28] = {};
  if (!pointer || read_user(addr, 4, (void *)pointer)) return 0;
  __u16 family = addr[0] | ((__u16)addr[1] << 8);
  if (family != 2 && family != 10) return 0;
  if (read_user(addr, family == 2 ? 16 : 28, (void *)pointer)) return 0;
  struct event e = {};
  __u64 id = pid_tgid(); e.cgroup = cgroup_id(); e.pid = id >> 32;
  e.family = family; e.port = ((__u16)addr[2] << 8) | addr[3]; e.kind = kind;
  if (family == 2) __builtin_memcpy(e.address, addr + 4, 4);
  else __builtin_memcpy(e.address, addr + 8, 16);
  get_comm(e.comm, sizeof(e.comm)); map_update(&pending, &id, &e, BPF_ANY); return 0;
}
static __always_inline int end(struct leave *ctx) {
  __u64 id = pid_tgid(); struct event *p = map_lookup(&pending, &id);
  if (!p) return 0;
  struct event *e = ring_reserve(&events, sizeof(*e), 0);
  if (e) { __builtin_memcpy(e, p, sizeof(*e)); e->result = ctx->ret; ring_submit(e, 0); }
  else { __u32 k = 0; __u64 *v = map_lookup(&dropped, &k); if (v) __sync_fetch_and_add(v, 1); }
  map_delete(&pending, &id); return 0;
}
SEC("tracepoint/syscalls/sys_enter_connect") int connect_enter(struct enter *ctx) { return begin(ctx->args[1], 1); }
SEC("tracepoint/syscalls/sys_exit_connect") int connect_exit(struct leave *ctx) { return end(ctx); }
SEC("tracepoint/syscalls/sys_enter_sendto") int sendto_enter(struct enter *ctx) { return begin(ctx->args[4], 2); }
SEC("tracepoint/syscalls/sys_exit_sendto") int sendto_exit(struct leave *ctx) { return end(ctx); }
char LICENSE[] SEC("license") = "Dual MIT/GPL";
