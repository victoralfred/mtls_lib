# Stress Test Guide

This document explains how to run stress tests, including the optimized version for 5 million connections.

## Quick Start

### Basic Stress Test (1K-1M connections)

```bash
# 1,000 connections
MTLS_STRESS_TEST=1 MTLS_STRESS_CONNECTIONS=1000 MTLS_STRESS_WORKERS=48 \
  go test -v -tags stress -run TestStressConnections -timeout 600s

# 10,000 connections
MTLS_STRESS_TEST=1 MTLS_STRESS_CONNECTIONS=10000 MTLS_STRESS_WORKERS=48 \
  go test -v -tags stress -run TestStressConnections -timeout 600s
```

### Optimized Stress Test (5M connections)

For 5 million connections, use the optimized implementation:

```bash
# Basic 5M test
MTLS_STRESS_TEST=1 go test -v -tags stress -run TestStress5M -timeout 3600s

# With custom workers and rate limiting
MTLS_STRESS_TEST=1 \
  MTLS_STRESS_WORKERS=128 \
  MTLS_STRESS_MAX_CONCURRENT=1000 \
  MTLS_STRESS_RATE_LIMIT=50000 \
  go test -v -tags stress -run TestStress5M -timeout 3600s
```

## Environment Variables

### Common Variables
- `MTLS_STRESS_TEST=1` - Required to enable stress tests
- `MTLS_STRESS_CONNECTIONS=N` - Total number of connections (default: 1000)
- `MTLS_STRESS_WORKERS=N` - Number of worker goroutines (default: 48)

### Optimized Test Variables
- `MTLS_STRESS_MAX_CONCURRENT=N` - Maximum concurrent connections at once (0 = unlimited)
- `MTLS_STRESS_RATE_LIMIT=N` - Maximum connections per second (0 = unlimited)

## Optimizations for 5M Connections

The optimized stress test (`stress_test_optimized.go`) includes:

1. **Worker Pool Pattern**: Reuses goroutines instead of creating new ones per connection
2. **Buffer Pooling**: Reuses buffers to reduce memory allocations
3. **Connection Rate Limiting**: Prevents overwhelming the system
4. **Max Concurrent Control**: Limits peak concurrent connections
5. **Batch Processing**: Processes connections in batches for better throughput
6. **Efficient Cleanup**: Faster shutdown and resource cleanup

## System Requirements

For 5M connections, ensure:

1. **File Descriptors**: Increase limit
   ```bash
   ulimit -n 1000000  # or higher
   ```

2. **Memory**: Estimate ~20KB per connection
   - 5M connections ≈ 100GB RAM (peak)
   - Use `MTLS_STRESS_MAX_CONCURRENT` to limit peak usage

3. **CPU**: More workers = more CPU usage
   - Recommended: 64-128 workers for 5M connections
   - Adjust based on your system

## Performance Tips

1. **Start Small**: Test with 1K, 10K, 100K before attempting 5M
2. **Monitor Resources**: Watch CPU, memory, and file descriptors during test
3. **Use Rate Limiting**: For 5M, start with `MTLS_STRESS_RATE_LIMIT=50000`
4. **Limit Concurrency**: Use `MTLS_STRESS_MAX_CONCURRENT=1000` to prevent resource exhaustion
5. **Increase Timeout**: 5M connections may take 10-30 minutes, use `-timeout 3600s`

## Example: Gradual Scale-Up

```bash
# Test 1: 1K connections
MTLS_STRESS_TEST=1 MTLS_STRESS_CONNECTIONS=1000 \
  go test -v -tags stress -run TestStressConnections

# Test 2: 100K connections
MTLS_STRESS_TEST=1 MTLS_STRESS_CONNECTIONS=100000 \
  go test -v -tags stress -run TestStressConnections

# Test 3: 1M connections (optimized)
MTLS_STRESS_TEST=1 MTLS_STRESS_WORKERS=64 \
  go test -v -tags stress -run TestStressConnectionsOptimized

# Test 4: 5M connections (optimized)
MTLS_STRESS_TEST=1 MTLS_STRESS_WORKERS=128 \
  MTLS_STRESS_MAX_CONCURRENT=2000 \
  MTLS_STRESS_RATE_LIMIT=100000 \
  go test -v -tags stress -run TestStress5M -timeout 3600s
```

## Troubleshooting

### Test Hangs or Times Out
- Increase timeout: `-timeout 3600s` or higher
- Reduce workers: `MTLS_STRESS_WORKERS=64`
- Add rate limiting: `MTLS_STRESS_RATE_LIMIT=50000`
- Limit concurrency: `MTLS_STRESS_MAX_CONCURRENT=1000`

### Out of Memory
- Reduce max concurrent: `MTLS_STRESS_MAX_CONCURRENT=500`
- Reduce workers: `MTLS_STRESS_WORKERS=32`
- Add rate limiting to slow down: `MTLS_STRESS_RATE_LIMIT=20000`

### Too Many File Descriptors
- Increase limit: `ulimit -n 1000000`
- Check current: `ulimit -n`
- Reduce max concurrent connections

### High Failure Rate
- Reduce connection rate: `MTLS_STRESS_RATE_LIMIT=10000`
- Increase workers gradually
- Check system resources (CPU, memory, network)

## Performance Metrics

The test reports:
- **Throughput**: Connections per second
- **Average Connect Time**: Time for TCP + TLS handshake
- **Max Concurrent**: Peak concurrent connections
- **Failure Rate**: Percentage of failed connections

Target metrics for 5M connections:
- Throughput: 10,000-50,000 connections/second
- Failure rate: < 1%
- Average connect time: < 10ms (local)

## Benchmark Results

### Test Environment
- **CPU**: AMD RYZEN AI MAX PRO 390 w/ Radeon 8050S
- **Cores**: 24
- **GOMAXPROCS**: 24
- **File Descriptor Limit**: 65535

### Results Summary

| Test Scale | Connections | Workers | Success Rate | Throughput | Avg Handshake | Duration |
|------------|-------------|---------|--------------|------------|---------------|----------|
| 10K        | 10,000      | 48      | 99.8%        | ~1,310/s   | 15.95ms       | ~7.6s    |
| 100K       | 100,000     | 48      | 99.8%        | ~1,305/s   | 16.06ms       | ~76.5s   |
| 1M         | 1,000,000   | 64      | 99.8%        | ~1,281/s   | 20.42ms       | ~779s    |

### Key Observations

1. **Consistent Throughput**: The library maintains ~1,280-1,310 connections/second across all scales (10K to 1M)
2. **Stable Handshake Time**: Average TLS handshake time ranges from 16-20ms depending on load
3. **High Reliability**: Success rate remains at 99.8% even at 1M connections
4. **Connection Recycling**: Workers process connections sequentially, avoiding FD exhaustion
5. **Linear Scaling**: Test duration scales linearly with connection count (no degradation)

### Notes
- Results may vary based on system load and network conditions
- The optimized stress test (`TestStressConnectionsOptimized`) and standard test (`TestStressConnections`) show similar performance
- Most failures are SSL_read timeouts, typically due to brief network congestion
