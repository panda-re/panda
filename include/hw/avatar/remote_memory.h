#ifndef HW_AVATAR_REMOTE_MEMORY_H
#define HW_AVATAR_REMOTE_MEMORY_H
enum RemoteMemoryOperation{
  AVATAR_READ,
  AVATAR_WRITE,
};



typedef struct MemoryForwardReq{
  uint64_t id;
  uint64_t pc;
  uint64_t address;
  uint64_t value;
  uint32_t size;
  enum RemoteMemoryOperation operation;

} MemoryForwardReq;

typedef struct RemoteMemoryResp{
    uint64_t id;
    uint64_t value;
    uint32_t success;
} RemoteMemoryResp;

typedef struct AvatarRMemoryState {
    SysBusDevice parent_obj;
    MemoryRegion iomem;
    uint64_t address;
    uint32_t size;
    uint64_t request_id;
    char *rx_queue_name;
    char *tx_queue_name;
    QemuAvatarMessageQueue *rx_queue;
    QemuAvatarMessageQueue *tx_queue;
    qemu_irq irq;
} AvatarRMemoryState;

uint64_t get_current_pc(void);

#endif
