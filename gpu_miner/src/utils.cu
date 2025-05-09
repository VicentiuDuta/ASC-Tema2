#include <stdio.h>
#include <stdint.h>
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <cuda_runtime.h>

// CUDA sprintf alternative for nonce finding. Converts integer to its string representation. Returns string's length.
__device__ int intToString(uint64_t num, char* out) {
    if (num == 0) {
        out[0] = '0';
        out[1] = '\0';
        return 1;
    }

    int i = 0;
    while (num != 0) {
        int digit = num % 10;
        num /= 10;
        out[i++] = '0' + digit;
    }

    // Reverse the string
    for (int j = 0; j < i / 2; j++) {
        char temp = out[j];
        out[j] = out[i - j - 1];
        out[i - j - 1] = temp;
    }
    out[i] = '\0';
    return i;
}

// CUDA strlen implementation.
__host__ __device__ size_t d_strlen(const char *str) {
    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len;
}

// CUDA strcpy implementation.
__device__ void d_strcpy(char *dest, const char *src) {
    int i = 0;
    while ((dest[i] = src[i]) != '\0') {
        i++;
    }
}

// CUDA strcat implementation.
__device__ void d_strcat(char *dest, const char *src) {
    while (*dest != '\0') {
        dest++;
    }
    while (*src != '\0') {
        *dest = *src;
        dest++;
        src++;
    }
    *dest = '\0';
}

// Compute SHA256 and convert to hex
__host__ __device__ void apply_sha256(const BYTE *input, BYTE *output) {
    size_t input_length = d_strlen((const char *)input);
    SHA256_CTX ctx;
    BYTE buf[SHA256_BLOCK_SIZE];
    const char hex_chars[] = "0123456789abcdef";

    sha256_init(&ctx);
    sha256_update(&ctx, input, input_length);
    sha256_final(&ctx, buf);

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        output[i * 2] = hex_chars[(buf[i] >> 4) & 0x0F];  // High nibble
        output[i * 2 + 1] = hex_chars[buf[i] & 0x0F];     // Low nibble
    }
    output[SHA256_BLOCK_SIZE * 2] = '\0'; // Null-terminate
}

// Compare two hashes
__host__ __device__ int compare_hashes(BYTE* hash1, BYTE* hash2) {
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
        if (hash1[i] < hash2[i]) {
            return -1; // hash1 is lower
        } else if (hash1[i] > hash2[i]) {
            return 1; // hash2 is lower
        }
    }
    return 0; // hashes are equal
}

// Kernel for computing transaction hashes
__global__ void compute_transaction_hashes_kernel(BYTE *transactions, BYTE *hashes, int transaction_size, int n) {
    unsigned int idx = threadIdx.x + blockDim.x * blockIdx.x;
    if (idx < n) {
        apply_sha256(transactions + idx * transaction_size, hashes + idx * SHA256_HASH_SIZE);
    }
}

// Kernel for constructing one level of the Merkle tree
__global__ void construct_merkle_level_kernel(BYTE *hashes, BYTE *next_level_hashes, int n) {
    __shared__ BYTE shared_hashes[256 * SHA256_HASH_SIZE];
    unsigned int tid = threadIdx.x;
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;

    // Încarcă hash-urile în shared memory
    if (idx < n) {
        // Copiază hash-ul din memoria globală în shared memory
        for (int i = 0; i < SHA256_HASH_SIZE; i++) {
            shared_hashes[tid * SHA256_HASH_SIZE + i] = hashes[idx * SHA256_HASH_SIZE + i];
        }
    }
    __syncthreads();

    // Calculează hash-urile pentru nivelul următor
    // Doar thread-urile care pot forma perechi valide
    if (tid < blockDim.x / 2 && blockIdx.x * blockDim.x / 2 + tid < (n + 1) / 2) {
        BYTE combined[2 * SHA256_HASH_SIZE];
        
        // Indexi în shared memory
        int local_idx1 = tid * 2;
        int local_idx2 = tid * 2 + 1;
        
        // Indexul global pentru primul hash din pereche
        int global_idx1 = blockIdx.x * blockDim.x + local_idx1;
        
        // Copiază primul hash
        d_strcpy((char*)combined, (const char*)&shared_hashes[local_idx1 * SHA256_HASH_SIZE]);
        
        // Verifică dacă al doilea hash există
        if (global_idx1 + 1 < n && local_idx2 < blockDim.x) {
            d_strcat((char*)combined, (const char*)&shared_hashes[local_idx2 * SHA256_HASH_SIZE]);
        } else {
            // Duplică primul hash dacă al doilea nu există
            d_strcat((char*)combined, (const char*)&shared_hashes[local_idx1 * SHA256_HASH_SIZE]);
        }
        
        // Calculează indexul pentru scrierea rezultatului în memoria globală
        int output_idx = blockIdx.x * blockDim.x / 2 + tid;
        
        // Calculează și scrie hash-ul combinat
        apply_sha256(combined, next_level_hashes + output_idx * SHA256_HASH_SIZE);
    }

}   

// CUDA implementation for constructing the Merkle root
void construct_merkle_root(int transaction_size, BYTE *transactions, int max_transactions_in_a_block, int n, BYTE merkle_root[SHA256_HASH_SIZE]) {
    // Handle edge cases
    if (n == 0) {
        memset(merkle_root, 0, SHA256_HASH_SIZE);
        return;
    }
    
    if (n == 1) {
        apply_sha256(transactions, merkle_root);
        return;
    }
    
    // Check for cudaMalloc success
    BYTE *d_transactions;
    // Check if device has enough memory
    cudaMalloc((void **) &d_transactions, n * transaction_size);
    cudaMemcpy(d_transactions, transactions, n * transaction_size, cudaMemcpyHostToDevice);
    
    // Device memory for current level hashes
    BYTE *d_current_hashes;
    cudaMalloc(&d_current_hashes, n * SHA256_HASH_SIZE);
    
    // Compute initial transaction hashes
    int threadsPerBlock = 256;
    int blocksPerGrid = (n + threadsPerBlock - 1) / threadsPerBlock;
    
    compute_transaction_hashes_kernel<<<blocksPerGrid, threadsPerBlock>>>(
        d_transactions, d_current_hashes, transaction_size, n
    );
    cudaDeviceSynchronize();
 
    // Free transaction memory as it's no longer needed
    cudaFree(d_transactions);
    
    // Construct the Merkle root
    int current_level_size = n;
    while (current_level_size > 1) {
        int next_level_size = (current_level_size + 1) / 2;
        BYTE *d_next_hashes;
        cudaMalloc(&d_next_hashes, next_level_size * SHA256_HASH_SIZE);
        // Compute the needed number of blocks
        int no_of_blocks = (current_level_size / threadsPerBlock);
        if (current_level_size % threadsPerBlock != 0) {
            no_of_blocks++;
        }

        // Launch kernel to construct next level of hashes
        construct_merkle_level_kernel<<<no_of_blocks, threadsPerBlock>>>(
            d_current_hashes, d_next_hashes, current_level_size
        );
        cudaDeviceSynchronize();

        cudaFree(d_current_hashes);
        // Allocate memory for the current level hashes
        cudaMalloc((void **)&d_current_hashes, next_level_size * SHA256_HASH_SIZE);
        // Copy the next level hashes to the current level
        cudaMemcpy(d_current_hashes, d_next_hashes, next_level_size * SHA256_HASH_SIZE, cudaMemcpyDeviceToDevice);
        cudaFree(d_next_hashes);
        current_level_size = next_level_size;
    }

    // Copy the final Merkle root to the host
    cudaMemcpy(merkle_root, d_current_hashes, SHA256_HASH_SIZE, cudaMemcpyDeviceToHost);
    cudaFree(d_current_hashes);
}


// CUDA implementation for finding a valid nonce
int find_nonce(BYTE *difficulty, uint32_t max_nonce, BYTE *block_content, size_t current_length, BYTE *block_hash, uint32_t *valid_nonce) {
    char nonce_string[NONCE_SIZE];

    for (uint32_t nonce = 0; nonce <= max_nonce; nonce++) {
        sprintf(nonce_string, "%u", nonce);
        strcpy((char *)block_content + current_length, nonce_string);
        apply_sha256(block_content, block_hash);

        if (compare_hashes(block_hash, difficulty) <= 0) {
            *valid_nonce = nonce;
            return 0;
        }
    }

    return 1;
}


__global__ void dummy_kernel() {}

// Warm-up function for the GPU
void warm_up_gpu() {
    BYTE *dummy_data;
    cudaMalloc((void **)&dummy_data, 256);
    dummy_kernel<<<1, 1>>>();
    cudaDeviceSynchronize();
    cudaFree(dummy_data);
}