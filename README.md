# Operating System Implementation Project

## Overview

This project involved designing and building a complete operating system with support for user programs and essential system calls. The implementation includes various key components, focusing on process management, multithreading, scheduling, and file system design.

## Key Features

### Process Control
- Implemented all necessary system calls for process management
- Support for creating new processes, waiting on processes, and process termination

### Multithreading
- Complete implementation of multithreaded program support
- Thread creation and management system calls
- Synchronization mechanisms using locks and semaphores
- Mutual exclusion guarantees for thread safety

### Priority Scheduler
- Implemented a priority-based scheduler
- Priority donation mechanism to prevent deadlock scenarios
- Efficient resource allocation based on thread priorities

### Alarm Clock
- Developed an efficient alarm clock for thread management
- Support for putting threads to sleep and waking them as needed
- Optimized timing mechanisms for system performance

### File System
- Complete file system implementation using inodes for data storage
- Support for extensible files with dynamic allocation
- Subdirectory functionality for hierarchical file organization
- Buffer cache implementation for efficient file retrieval
- Synchronization mechanisms to prevent concurrent file modification

## Technical Details

The project demonstrates a comprehensive understanding of operating system principles, including:
- System call implementation and handling
- Process and thread management
- Concurrency control and synchronization
- File system design and implementation
- Memory management and optimization