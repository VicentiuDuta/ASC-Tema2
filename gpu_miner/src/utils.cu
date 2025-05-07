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
        return 2;
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
__device__ void d_strcpy(char *dest, const char *src){
    int i = 0;
    while ((dest[i] = src[i]) != '\0') {
        i++;
    }
}

// CUDA strcat implementation.
__device__ void d_strcat(char *dest, const char *src){
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
        output[i * 2]     = hex_chars[(buf[i] >> 4) & 0x0F];  // High nibble
        output[i * 2 + 1] = hex_chars[buf[i] & 0x0F];         // Low nibble
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
__global__ void compute_transaction_hashes_kernel(BYTE *transactions, BYTE *hashes, int transaction_size, int n) {
    unsigned int idx = threadIdx.x + blockDim.x * blockIdx.x;
    if (idx < n) {
        apply_sha256(transactions + idx * transaction_size, hashes + idx * SHA256_HASH_SIZE);
    }
}

__global__ void construct_merkle_level_kernel(BYTE *hashes, int n, BYTE *device_next_hashes) {
        // Allocate shared memory for the current level
        __shared__ BYTE shared_hashes[256 * SHA256_HASH_SIZE];
        unsigned int tid = threadIdx.x;
        unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;

        // Load the hashes into shared memory 
        if (idx < n) {
            for (int i = 0; i < SHA256_HASH_SIZE; i++) {
                shared_hashes[tid * SHA256_HASH_SIZE + i] = hashes[idx * SHA256_HASH_SIZE + i];
            }
        } 
        
        // Synchronize threads to ensure all data is loaded
        __syncthreads();
        
        // Compute the next level of hashes only with the first half of threads
        if (idx < n / 2) {
            BYTE combined_hash[2 * SHA256_HASH_SIZE];
            int idx1 = tid * 2;
            int idx2 = tid * 2 + 1;

            // Copy the first hash
            d_strcpy((char *) combined_hash, (const char *) (shared_hashes + idx1 * SHA256_HASH_SIZE));
            // If the second hash exists, concatenate it
            if (idx2 < blockDim.x && idx * 2 + 1 < n) {
                d_strcat((char *) combined_hash, (const char *) (shared_hashes + idx2 * SHA256_HASH_SIZE));
            } else {
                // If the second hash does not exist, duplicate the first hash
                d_strcat((char *) combined_hash, (const char *) (shared_hashes + idx1 * SHA256_HASH_SIZE));
            }
            
            // Compute the hash of the combined hashes
            apply_sha256((BYTE *) combined_hash, device_next_hashes + idx * SHA256_HASH_SIZE);
        }
} 

// TODO 1: Implement this function in CUDA
void construct_merkle_root(int transaction_size, BYTE *transactions, int max_transactions_in_a_block, int n, BYTE merkle_root[SHA256_HASH_SIZE]) {
    BYTE (*hashes)[SHA256_HASH_SIZE] = (BYTE (*)[SHA256_HASH_SIZE])malloc(max_transactions_in_a_block * SHA256_HASH_SIZE);
    // Allocate device memory for transactions
    BYTE *device_transactions;
    cudaMalloc((void **) &device_transactions, n * transaction_size);

    // Allocate device memory for hashes
    BYTE *device_hashes;
    cudaMalloc((void **) &device_hashes, n * SHA256_HASH_SIZE);

    // Copy transactions to device
    cudaMemcpy(device_transactions, transactions, n * transaction_size, cudaMemcpyHostToDevice);


    // Declare kernel parameters
    const size_t block_size = 256;
    size_t num_blocks = n / block_size;
    if (n % block_size != 0) {
        num_blocks++;
    }

    // Launch kernel to compute transaction hashes
    compute_transaction_hashes_kernel<<<num_blocks, block_size>>>(device_transactions, device_hashes, transaction_size, n);
    // Wait for kernel to finish
    cudaDeviceSynchronize();

    // Free device memory
    cudaFree(device_transactions);
    
    // Allocate device memory for next level hashes
    BYTE *device_next_hashes;
    cudaMalloc((void **) &device_next_hashes, (n / 2 + n % 2) * SHA256_HASH_SIZE);

    while (n > 1) {
        int new_n = n / 2;
        if (n % 2 != 0)
            new_n++; // if odd, duplicate last hash

        num_blocks = n / block_size;
        if(n % block_size != 0) {
            num_blocks++; // round up
        }

        construct_merkle_level_kernel<<<num_blocks, block_size>>>(device_hashes, n, device_next_hashes);
        cudaDeviceSynchronize();

        // Copy the next level hashes to the device
        BYTE *temp = device_hashes;
        device_hashes = device_next_hashes;
        device_next_hashes = temp;
        n = new_n;
    }

    // Copy the final merkle root to host
    cudaMemcpy(merkle_root, device_hashes, SHA256_HASH_SIZE, cudaMemcpyDeviceToHost);
    // Free device memory
    cudaFree(device_hashes);
    cudaFree(device_next_hashes);
    // Free host memory
    free(hashes);

}

void find_nonce_kernel(BYTE *difficulty, uint32_t max_nonce, BYTE *block_content, size_t current_length, BYTE *block_hash, uint32_t *valid_nonce, uint32_t *found_nonce_flag) {

}

// TODO 2: Implement this function in CUDA
int find_nonce(BYTE *difficulty, uint32_t max_nonce, BYTE *block_content, size_t current_length, BYTE *block_hash, uint32_t *valid_nonce) {
    // Allocate device memory for block content
    BYTE *device_difficulty;
    cudaMalloc((void **) &device_difficulty, SHA256_HASH_SIZE);
    cudaMemcpy(device_difficulty, difficulty, SHA256_HASH_SIZE, cudaMemcpyHostToDevice);

    BYTE *device_block_content;
    cudaMalloc((void **) &device_block_content, current_length);
    cudaMemcpy(device_block_content, block_content, current_length, cudaMemcpyHostToDevice);

    BYTE *device_block_hash;
    cudaMalloc((void **) &device_block_hash, SHA256_HASH_SIZE);
    cudaMemcpy(device_block_hash, block_hash, SHA256_HASH_SIZE, cudaMemcpyHostToDevice);

    uint32_t *device_valid_nonce;
    cudaMalloc((void **) &device_valid_nonce, sizeof(uint32_t));

    int* device_found_nonce;
    cudaMalloc((void **) &device_found_nonce, sizeof(int));
    cudaMemset(device_found_nonce, 0, sizeof(int));

    // Declare kernel parameters
    const size_t block_size = 512;
    size_t num_blocks = max_nonce / block_size;
    if (max_nonce % block_size != 0) {
        num_blocks++;
    }
}


__global__ void dummy_kernel() {}

// Warm-up function
void warm_up_gpu() {
    BYTE *dummy_data;
    cudaMalloc((void **)&dummy_data, 256);
    dummy_kernel<<<1, 1>>>();
    cudaDeviceSynchronize();
    cudaFree(dummy_data);
}
