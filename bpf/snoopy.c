#include <linux/ptrace.h>

#define TASK_COMM_LEN 16
#define MAX_DATA_SIZE 10000

// Enumeration for identifying SSL functions.
enum Function {
    SSL_READ,
    SSL_WRITE
};

// Struct for storing TLS related data.
struct TLS_MESSAGE {
    uint64_t elapsed;
    uint32_t pid;              // Process ID
    uint32_t tid;              // Thread ID
    int retval;
    enum Function function;
    char process_name[TASK_COMM_LEN];
    char message[MAX_DATA_SIZE];
};

// eBPF data structures.
BPF_HASH(tls_map_data, u64, const char *);
BPF_HASH(tls_map_timestamp, u64, u64);
BPF_PERF_OUTPUT(TLS_DATA_PERF_OUTPUT);
BPF_PERCPU_ARRAY(tls_data_array, struct TLS_MESSAGE);

// Utility function to extract the process ID from a PID-TID combo.
static inline u32 extractProcessID(u64 ptID) {
    return ptID >> 32;
}

// Utility function to extract the thread ID from a PID-TID combo.
static inline u32 extractThreadID(u64 ptID) {
    return (u32) ptID;
}

// Function to send TLS message data to a perf event.
static inline int send_tls_message_to_perf(struct pt_regs* ctx, u32 bufferLen, u64 id, const char * buffer, enum Function function) {
    u32 zeroPointer = 0;
    struct TLS_MESSAGE* tlsMessage = tls_data_array.lookup(&zeroPointer);
    
    if (!tlsMessage) {
        return 0;
    }

    // Extract and populate PID and TID from the combined ID.
    tlsMessage->pid = extractProcessID(id);
    tlsMessage->tid = extractThreadID(id);

    u64 *et = tls_map_timestamp.lookup(&id);
    if (!et) {
        return 0;
    }

    // Get the current command name and elapsed time.
    bpf_get_current_comm(&tlsMessage->process_name, sizeof(tlsMessage->process_name));
    tlsMessage->elapsed = bpf_ktime_get_ns() - *et;

    // Copy data from user space to kernel space.
    u32 outputBufferLen = bufferLen < MAX_DATA_SIZE ? bufferLen : MAX_DATA_SIZE;
    bpf_probe_read(&tlsMessage->retval, sizeof(int), (void*)PT_REGS_RC(ctx));
    bpf_probe_read(tlsMessage->message, outputBufferLen, buffer);

    tlsMessage->function = function;

    // Submit data to perf event.
    TLS_DATA_PERF_OUTPUT.perf_submit(ctx, tlsMessage, sizeof(*tlsMessage));

    // Clean up maps.
    tls_map_data.delete(&id);
    tls_map_timestamp.delete(&id);

    return 0;
}

// Function to handle entry into SSL functions.
static inline int handle_uprobe_entry(struct pt_regs* ctx, enum Function function) {
    u64 processThreadID = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    const char* buffer = (const char*)PT_REGS_PARM2(ctx);

    // Store timestamp and buffer pointer in maps.
    tls_map_timestamp.update(&processThreadID, &ts);
    tls_map_data.update(&processThreadID, &buffer);

    return 0;
}

// Function to handle return from SSL functions.
static inline int handle_uprobe_return(struct pt_regs* ctx, enum Function function) {
    u64 processThreadID = bpf_get_current_pid_tgid();
    const char** buffer = tls_map_data.lookup(&processThreadID);

    if (!buffer) {
        return 0;
    }

    int len = (int)PT_REGS_RC(ctx);
    if (len >= 0) {
        send_tls_message_to_perf(ctx, len, processThreadID, *buffer, function);
    }

    return 0;
}

// Uprobe functions for SSL write.
int uprobe_entry_SSL_write(struct pt_regs* ctx) {
    return handle_uprobe_entry(ctx, SSL_WRITE);
}

int uprobe_return_SSL_write(struct pt_regs* ctx) {
    return handle_uprobe_return(ctx, SSL_WRITE);
}

// Uprobe functions for SSL read.
int uprobe_entry_SSL_read(struct pt_regs* ctx) {
    return handle_uprobe_entry(ctx, SSL_READ);
}

int uprobe_return_SSL_read(struct pt_regs* ctx) {
    return handle_uprobe_return(ctx, SSL_READ);
}

