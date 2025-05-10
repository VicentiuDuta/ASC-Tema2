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
__global__ void construct_merkle_level_kernel(BYTE *hashes, int n, int next_n) {
    unsigned int idx = threadIdx.x + blockDim.x * blockIdx.x;
    
    if (idx < next_n) {
        BYTE combined[2 * SHA256_HASH_SIZE];
        
        d_strcpy((char*)combined, (const char*)(hashes + (idx * 2) * SHA256_HASH_SIZE));
        
        if (idx * 2 + 1 < n) {
            d_strcat((char*)combined, (const char*)(hashes + (idx * 2 + 1) * SHA256_HASH_SIZE));
        } else {
            d_strcat((char*)combined, (const char*)(hashes + (idx * 2) * SHA256_HASH_SIZE));
        }
        
        apply_sha256(combined, hashes + idx * SHA256_HASH_SIZE);
    }

}   

// CUDA implementation for constructing the Merkle root
void construct_merkle_root(int transaction_size, BYTE *transactions, int max_transactions_in_a_block, int n, BYTE merkle_root[SHA256_HASH_SIZE]) {
    // Check for cudaMalloc success
    BYTE *d_transactions;
    cudaMalloc((void **) &d_transactions, n * transaction_size);
    cudaMemcpy(d_transactions, transactions, n * transaction_size, cudaMemcpyHostToDevice);
    
    // Device memory for current level hashes
    BYTE *d_current_hashes;
    cudaMalloc((void **) &d_current_hashes, n * SHA256_HASH_SIZE);
    
    // Compute initial transaction hashes
    int threadsPerBlock = 256;
    int blocksPerGrid = (n + threadsPerBlock - 1) / threadsPerBlock;
    
    compute_transaction_hashes_kernel<<<blocksPerGrid, threadsPerBlock>>>(
        d_transactions, d_current_hashes, transaction_size, n
    );
    cudaDeviceSynchronize();
    
    // Construct the Merkle root
    int current_level_size = n;
    while (current_level_size > 1) {
        int next_level_size = (current_level_size + 1) / 2;
        int no_of_blocks = (next_level_size + threadsPerBlock - 1) / threadsPerBlock;
        
        // Launch kernel to construct next level of hashes
        construct_merkle_level_kernel<<<no_of_blocks, threadsPerBlock>>>(
            d_current_hashes,current_level_size, next_level_size
        );
        cudaDeviceSynchronize();
        
        current_level_size = next_level_size;
    }
    
    // Copy the final Merkle root to the host
    cudaMemcpy(merkle_root, d_current_hashes, SHA256_HASH_SIZE, cudaMemcpyDeviceToHost);
    
    // Free transaction memory as it's no longer needed
    cudaFree(d_transactions);
    cudaFree(d_current_hashes);
}



// Specialized kernel for nonce search - designed for maximum throughput
__global__ void find_nonce_kernel(BYTE *difficulty, uint32_t max_nonce, BYTE *block_content, 
    size_t current_length, BYTE *block_hash, 
    uint32_t *valid_nonce, int *found_flag) {
    // Thread identifiers
    uint32_t tid = threadIdx.x;
    uint32_t global_id = blockIdx.x * blockDim.x + tid;
    uint32_t total_threads = blockDim.x * gridDim.x;

    // Load difficulty pattern into shared memory for faster access
    __shared__ BYTE shared_difficulty[SHA256_HASH_SIZE];
    if (tid < SHA256_HASH_SIZE) {
    shared_difficulty[tid] = difficulty[tid];
    }
    __syncthreads();

    // Prepare local copy of block content
    BYTE local_block[BLOCK_SIZE];
    for (size_t i = 0; i < current_length; i++) {
    local_block[i] = block_content[i];
    }
    local_block[current_length] = '\0';

    // Process nonces with efficient striping
    for (uint32_t nonce = global_id; nonce <= max_nonce && !(*found_flag); nonce += total_threads) {
    // Format nonce as string
    char nonce_str[NONCE_SIZE];
    int len = intToString(nonce, nonce_str);

    // Append nonce to block content
    d_strcpy((char*)(local_block + current_length), nonce_str);

    // Calculate hash
    BYTE hash[SHA256_HASH_SIZE];
    apply_sha256(local_block, hash);

    // Quick check for first few characters (most will fail here)
    if (hash[0] <= shared_difficulty[0]) {
    // If first character matches, do a more thorough check
    bool is_valid = true;

    // Direct character comparison for speed - unrolled loop
    if (hash[0] == shared_difficulty[0]) {
    #pragma unroll 4
    for (int i = 1; i < 5; i++) {
    if (hash[i] > shared_difficulty[i]) {
    is_valid = false;
    break;
    } 
    else if (hash[i] < shared_difficulty[i]) {
    break; // Hash is definitely smaller
    }
    }

    // Only do a full comparison if the first 5 chars indicate a match
    if (is_valid && compare_hashes(hash, shared_difficulty) > 0) {
    is_valid = false;
    }
    }

    // If we found a valid hash
    if (is_valid) {
    // Atomically check and set the found flag
    if (atomicCAS(found_flag, 0, 1) == 0) {
    // We're the first to find a solution
    *valid_nonce = nonce;

    // Copy the hash result
    for (int i = 0; i < SHA256_HASH_SIZE; i++) {
    block_hash[i] = hash[i];
    }
    }
    return; // Exit immediately
}
}
}
}

// Host function to find a valid nonce
int find_nonce(BYTE *difficulty, uint32_t max_nonce, BYTE *block_content,  size_t current_length, BYTE *block_hash, uint32_t *valid_nonce) {
    // Device memory pointers
    BYTE *d_difficulty, *d_block_content, *d_block_hash;
    uint32_t *d_valid_nonce;
    int *d_found_flag;

    // Allocate device memory
    cudaMalloc(&d_difficulty, SHA256_HASH_SIZE);
    cudaMalloc(&d_block_content, current_length + NONCE_SIZE);
    cudaMalloc(&d_block_hash, SHA256_HASH_SIZE);
    cudaMalloc(&d_valid_nonce, sizeof(uint32_t));
    cudaMalloc(&d_found_flag, sizeof(int));

    // Copy input data to device
    cudaMemcpy(d_difficulty, difficulty, SHA256_HASH_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpy(d_block_content, block_content, current_length, cudaMemcpyHostToDevice);
    cudaMemset(d_found_flag, 0, sizeof(int));

    // Query device properties for optimal launch configuration
    cudaDeviceProp props;
    cudaGetDeviceProperties(&props, 0);

    // Determine optimal launch configuration based on GPU
    const int threadsPerBlock = 256;
    const int maxBlocksPerSM = 48; // Tesla K40m has 15 SMs, each can handle up to 16 blocks
    const int numBlocks = props.multiProcessorCount * maxBlocksPerSM;

    // Launch kernel
    find_nonce_kernel<<<numBlocks, threadsPerBlock>>>(
        d_difficulty, max_nonce, d_block_content, current_length,
        d_block_hash, d_valid_nonce, d_found_flag
    );

    // Wait for completion
    cudaDeviceSynchronize();

    // Check if a valid nonce was found
    int found = 0;
    cudaMemcpy(&found, d_found_flag, sizeof(int), cudaMemcpyDeviceToHost);

    if (found) {
        // Copy results back to host
        cudaMemcpy(valid_nonce, d_valid_nonce, sizeof(uint32_t), cudaMemcpyDeviceToHost);
        cudaMemcpy(block_hash, d_block_hash, SHA256_HASH_SIZE, cudaMemcpyDeviceToHost);
    }

    // Clean up device memory
    cudaFree(d_difficulty);
    cudaFree(d_block_content);
    cudaFree(d_block_hash);
    cudaFree(d_valid_nonce);
    cudaFree(d_found_flag);

    // Return 0 if a valid nonce was found, 1 otherwise
    return found ? 0 : 1;
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