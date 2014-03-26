#ifndef __PIRATE_MARK_H__
#define __PIRATE_MARK_H__

#define vm_query_buffer(buf, len, name, name_len, offset) \
{ \
    void *b = buf; \
    int l = len; \
	void *n_ptr = name; \
	int n_l = name_len; \
	int off = offset; \
    \
    __asm { \
        __asm PUSH EAX \
        __asm PUSH EBX \
        __asm PUSH ECX \
		__asm PUSH EDI \
		__asm PUSH ESI \
		__asm PUSH EDX \
        __asm MOV EAX, 9 \
        __asm MOV EBX, b \
        __asm MOV ECX, l \
		__asm MOV EDI, n_ptr \
		__asm MOV ESI, n_l \
		__asm MOV EDX, off \
        __asm CPUID \
		__asm POP EDX \
		__asm POP ESI \
		__asm POP EDI \
        __asm POP ECX \
        __asm POP EBX \
        __asm POP EAX \
    }; \
}


#define vm_label_buffer(buf, buf_len, label, label_len) \
{ \
    void *b_ptr = buf; \
    int b_len = buf_len; \
    void *l_ptr = label; \
    int l_len = label_len; \
    \
    __asm { \
        __asm PUSH EAX \
        __asm PUSH EBX \
        __asm PUSH ECX \
        __asm PUSH EDI \
        __asm PUSH ESI \
        __asm MOV EAX, 7 \
        __asm MOV EBX, b_ptr \
        __asm MOV ECX, b_len \
        __asm MOV EDI, l_ptr \
        __asm MOV ESI, l_len \
        __asm CPUID \
        __asm POP ESI \
        __asm POP EDI \
        __asm POP ECX \
        __asm POP EBX \
        __asm POP EAX \
    }; \
}

#define vm_label_buffer_pos(buf, buf_len, label, label_len, offset) \
{ \
    void *b_ptr = buf; \
    int b_len = buf_len; \
    void *l_ptr = label; \
    int l_len = label_len; \
	int off = offset; \
    \
    __asm { \
        __asm PUSH EAX \
        __asm PUSH EBX \
        __asm PUSH ECX \
        __asm PUSH EDI \
        __asm PUSH ESI \
		__asm PUSH EDX \
        __asm MOV EAX, 8 \
        __asm MOV EBX, b_ptr \
        __asm MOV ECX, b_len \
        __asm MOV EDI, l_ptr \
        __asm MOV ESI, l_len \
		__asm MOV EDX, off \
        __asm CPUID \
		__asm POP EDX \
        __asm POP ESI \
        __asm POP EDI \
        __asm POP ECX \
        __asm POP EBX \
        __asm POP EAX \
    }; \
}

#define vm_guest_util_done() \
{ \
    __asm { \
        __asm PUSH EAX \
        __asm MOV EAX, 10 \
        __asm CPUID \
        __asm POP EAX \
    }; \
}

#endif /* __PIRATE_MARK_H__ */
