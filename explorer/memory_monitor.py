import os
import signal
import threading
import time
import resource
import sys
import atexit
import fcntl
from pathlib import Path
from typing import Optional, Callable

from utils.logging_config import get_logger

logger = get_logger(__name__)


# ============================================================================
# Process Registry for Adaptive Memory Limits
# ============================================================================

class ProcessRegistry:
    """
    Registry for tracking active TAExplorer processes.
    
    Uses a shared directory with lock files to coordinate between processes.
    Each process registers itself and the registry can count active processes
    to enable adaptive memory limits.
    """
    
    DEFAULT_REGISTRY_DIR = "/tmp/ta_explorer_processes"
    
    def __init__(self, registry_dir: Optional[str] = None):
        """
        Initialize the process registry.
        
        Args:
            registry_dir: Directory to store process registration files.
                         Defaults to /tmp/ta_explorer_processes
        """
        self.registry_dir = Path(registry_dir or self.DEFAULT_REGISTRY_DIR)
        self.pid = os.getpid()
        self.registered = False
        self._lock_file = None
        self._lock_fd = None
        
    def _ensure_registry_dir(self):
        """Create registry directory if it doesn't exist."""
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        
    def _get_pid_file(self, pid: Optional[int] = None) -> Path:
        """Get the path to a process's registration file."""
        return self.registry_dir / f"{pid or self.pid}.lock"
    
    def register(self):
        """
        Register this process in the registry.
        Creates a lock file that persists while the process runs.
        """
        if self.registered:
            return
            
        self._ensure_registry_dir()
        
        pid_file = self._get_pid_file()
        try:
            # Create and lock the file (exclusive lock)
            self._lock_fd = open(pid_file, 'w')
            fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            
            # Write process info
            self._lock_fd.write(f"{self.pid}\n{time.time()}\n")
            self._lock_fd.flush()
            
            self.registered = True
            logger.debug(f"Process {self.pid} registered in {self.registry_dir}")
            
            # Register cleanup on exit
            atexit.register(self.unregister)
            
        except (IOError, OSError) as e:
            logger.warning(f"Failed to register process: {e}")
            if self._lock_fd:
                self._lock_fd.close()
                self._lock_fd = None
    
    def unregister(self):
        """
        Unregister this process from the registry.
        Called automatically on exit.
        """
        if not self.registered:
            return
            
        try:
            if self._lock_fd:
                fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_UN)
                self._lock_fd.close()
                self._lock_fd = None
            
            pid_file = self._get_pid_file()
            if pid_file.exists():
                pid_file.unlink()
                
            self.registered = False
            logger.debug(f"Process {self.pid} unregistered")
            
        except Exception as e:
            logger.warning(f"Error unregistering process: {e}")
    
    def _is_process_alive(self, pid: int) -> bool:
        """Check if a process is still running."""
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    
    def _cleanup_stale_entries(self):
        """Remove registration files for dead processes."""
        if not self.registry_dir.exists():
            return
            
        for pid_file in self.registry_dir.glob("*.lock"):
            try:
                pid = int(pid_file.stem)
                if not self._is_process_alive(pid):
                    pid_file.unlink()
                    logger.debug(f"Cleaned up stale entry for PID {pid}")
            except (ValueError, OSError):
                pass
    
    def count_active_processes(self) -> int:
        """
        Count the number of active registered processes.
        Also cleans up stale entries from dead processes.
        """
        if not self.registry_dir.exists():
            return 1  # At least this process
            
        self._cleanup_stale_entries()
        
        count = 0
        for pid_file in self.registry_dir.glob("*.lock"):
            try:
                pid = int(pid_file.stem)
                if self._is_process_alive(pid):
                    count += 1
            except (ValueError, OSError):
                pass
        
        return max(1, count)  # At least 1 process
    
    def get_process_pids(self) -> list:
        """Get list of active registered process PIDs."""
        if not self.registry_dir.exists():
            return [self.pid]
            
        self._cleanup_stale_entries()
        
        pids = []
        for pid_file in self.registry_dir.glob("*.lock"):
            try:
                pid = int(pid_file.stem)
                if self._is_process_alive(pid):
                    pids.append(pid)
            except (ValueError, OSError):
                pass
        
        return pids if pids else [self.pid]


def get_total_system_memory_gb() -> float:
    """Get total system memory in GB."""
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    # MemTotal is in KB
                    kb = int(line.split()[1])
                    return kb / (1024 * 1024)
    except Exception:
        pass
    
    # Fallback: use os.sysconf
    try:
        pages = os.sysconf('SC_PHYS_PAGES')
        page_size = os.sysconf('SC_PAGE_SIZE')
        return (pages * page_size) / (1024 * 1024 * 1024)
    except Exception:
        return 64.0  # Default fallback


def get_available_system_memory_gb() -> float:
    """Get available system memory in GB."""
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemAvailable:'):
                    kb = int(line.split()[1])
                    return kb / (1024 * 1024)
    except Exception:
        pass
    
    return get_total_system_memory_gb() * 0.8  # Fallback: assume 80% available


# Global registry instance
_global_registry: Optional[ProcessRegistry] = None


def get_process_registry() -> ProcessRegistry:
    """Get or create the global process registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = ProcessRegistry()
    return _global_registry


class MemoryLimitExceeded(Exception):
    """Exception raised when memory limit is exceeded."""
    def __init__(self, current_mb: float, limit_mb: float):
        self.current_mb = current_mb
        self.limit_mb = limit_mb
        super().__init__(f"Memory limit exceeded: {current_mb:.1f}MB / {limit_mb:.1f}MB")


def _generate_report_directly():
    """
    Generate the report directly from the monitor thread.
    This is a fallback when signal handlers don't respond.
    """
    try:
        logger.info("Generating report directly from memory monitor...")
        from reporting import finalize_report, add_syscall_stats
        from explorer.hooks import get_syscall_stats
        
        # Add syscall statistics to the report
        syscall_stats = get_syscall_stats()
        add_syscall_stats(syscall_stats)
        
        # Finalize and generate HTML report
        report_path = finalize_report()
        logger.info(f"HTML Report generated successfully at: {report_path}")
        return True
    except Exception as e:
        logger.error(f"Error generating report directly: {e}")
        import traceback
        traceback.print_exc()
        return False


class MemoryMonitor:
    """
    Memory monitoring module for TAExplorer.

    This module provides memory limit enforcement to prevent OOM kills.
    When the memory limit is approached, it triggers graceful shutdown
    allowing reports to be generated before the process is terminated.

    Supports adaptive memory limits that adjust based on the number of
    active processes sharing the system memory.

    Usage:
        # Fixed limit
        monitor = MemoryMonitor(limit_gb=100)
        monitor.start()
        
        # Adaptive limit (shares 900GB among all processes)
        monitor = MemoryMonitor(total_memory_gb=900, adaptive=True)
        monitor.start()
        
        # Check periodically in your code:
        if monitor.limit_exceeded:
            raise MemoryLimitExceeded(...)
        
        # Or let the monitor send SIGTERM automatically
    """
    
    def __init__(
        self, 
        limit_gb: Optional[float] = None,
        total_memory_gb: Optional[float] = None,
        adaptive: bool = False,
        min_limit_gb: float = 5.0,
        max_limit_gb: Optional[float] = None,
        check_interval: float = 5.0,
        threshold_percent: float = 0.95,
        auto_signal: bool = True,
        shutdown_timeout: float = 30.0,
        callback: Optional[Callable[[], None]] = None
    ):
        """
        Initialize the memory monitor.
        
        Args:
            limit_gb: Fixed memory limit in gigabytes (used if adaptive=False)
            total_memory_gb: Total memory pool to share (used if adaptive=True).
                            If None, uses system total memory.
            adaptive: If True, dynamically adjust limit based on active processes
            min_limit_gb: Minimum limit per process in adaptive mode (default: 5GB)
            max_limit_gb: Maximum limit per process in adaptive mode (default: None = no max)
            check_interval: How often to check memory usage in seconds (default: 5s)
            threshold_percent: Trigger at this percentage of limit (default: 95%)
            auto_signal: If True, send SIGTERM when limit exceeded (default: True)
            shutdown_timeout: Seconds to wait for graceful shutdown before forcing (default: 30s)
            callback: Optional callback function to call when limit exceeded
        """
        self.adaptive = adaptive
        self.min_limit_gb = min_limit_gb
        self.max_limit_gb = max_limit_gb
        self.threshold_percent = threshold_percent
        self.check_interval = check_interval
        self.auto_signal = auto_signal
        self.shutdown_timeout = shutdown_timeout
        self.callback = callback
        
        # Determine total memory pool for adaptive mode
        if adaptive:
            if total_memory_gb is not None:
                self.total_memory_gb = total_memory_gb
            else:
                # Use 90% of system memory as the pool
                self.total_memory_gb = get_total_system_memory_gb() * 0.9
            
            # Register with process registry
            self._registry = get_process_registry()
            self._registry.register()
            
            # Calculate initial limit
            self._update_adaptive_limit()
            logger.info(f"MemoryMonitor initialized in ADAPTIVE mode: "
                       f"total_pool={self.total_memory_gb:.1f}GB, "
                       f"min={min_limit_gb}GB, "
                       f"initial_limit={self.limit_mb/1024:.1f}GB")
        else:
            # Fixed limit mode
            if limit_gb is None:
                limit_gb = 100.0  # Default
            self._registry = None
            self.total_memory_gb = None
            self._set_limit_gb(limit_gb)
            logger.info(f"MemoryMonitor initialized: limit={limit_gb}GB, threshold={threshold_percent*100}%")
        
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._limit_exceeded = False
        self._current_memory_mb = 0.0
        self._lock = threading.Lock()
        self._shutdown_in_progress = False
        self._last_limit_update = 0
        self._limit_update_interval = 30  # Update adaptive limit every 30 seconds
    
    def _set_limit_gb(self, limit_gb: float):
        """Set the memory limit in GB."""
        self.limit_bytes = int(limit_gb * 1024 * 1024 * 1024)
        self.limit_mb = limit_gb * 1024
        self.threshold_bytes = int(self.limit_bytes * self.threshold_percent)
    
    def _update_adaptive_limit(self):
        """Update the memory limit based on active processes."""
        if not self.adaptive or self._registry is None:
            return
        
        active_count = self._registry.count_active_processes()
        
        # Calculate per-process share
        limit_gb = self.total_memory_gb / active_count
        
        # Apply min/max constraints
        limit_gb = max(limit_gb, self.min_limit_gb)
        if self.max_limit_gb is not None:
            limit_gb = min(limit_gb, self.max_limit_gb)
        
        old_limit_mb = getattr(self, 'limit_mb', 0)
        self._set_limit_gb(limit_gb)
        
        if abs(old_limit_mb - self.limit_mb) > 100:  # Log if changed by more than 100MB
            logger.info(f"Adaptive limit updated: {self.limit_mb/1024:.1f}GB "
                       f"(pool={self.total_memory_gb:.1f}GB / {active_count} processes)")
    
    def get_adaptive_info(self) -> dict:
        """Get information about adaptive limit status."""
        if not self.adaptive:
            return {'adaptive': False, 'limit_gb': self.limit_mb / 1024}
        
        active_count = self._registry.count_active_processes() if self._registry else 1
        return {
            'adaptive': True,
            'total_pool_gb': self.total_memory_gb,
            'active_processes': active_count,
            'limit_gb': self.limit_mb / 1024,
            'min_limit_gb': self.min_limit_gb,
            'max_limit_gb': self.max_limit_gb,
        }
    
    @property
    def limit_exceeded(self) -> bool:
        """Check if the memory limit has been exceeded."""
        with self._lock:
            return self._limit_exceeded
    
    @property
    def current_memory_mb(self) -> float:
        """Get the current memory usage in MB."""
        with self._lock:
            return self._current_memory_mb
    
    def get_memory_usage_bytes(self) -> int:
        """Get current RSS memory usage in bytes."""
        try:
            # Read from /proc/self/statm for accurate RSS
            with open('/proc/self/statm', 'r') as f:
                # statm format: size resident shared text lib data dt
                # resident is in pages, typically 4KB each
                parts = f.read().split()
                resident_pages = int(parts[1])
                page_size = os.sysconf('SC_PAGE_SIZE')
                return resident_pages * page_size
        except Exception:
            # Fallback to resource module
            usage = resource.getrusage(resource.RUSAGE_SELF)
            # ru_maxrss is in KB on Linux
            return usage.ru_maxrss * 1024
    
    def get_memory_usage_mb(self) -> float:
        """Get current RSS memory usage in MB."""
        return self.get_memory_usage_bytes() / (1024 * 1024)
    
    def get_memory_usage_gb(self) -> float:
        """Get current RSS memory usage in GB."""
        return self.get_memory_usage_bytes() / (1024 * 1024 * 1024)
    
    def _try_graceful_shutdown(self):
        """
        Attempt graceful shutdown with multiple strategies.
        """
        if self._shutdown_in_progress:
            return
        self._shutdown_in_progress = True
        
        # Strategy 1: Generate report directly from this thread
        # This works even if the main thread is blocked
        logger.info("Attempting to generate report directly...")
        report_generated = _generate_report_directly()
        
        if report_generated:
            logger.info("Report generated successfully, exiting...")
            # Use os._exit to bypass any blocked threads
            os._exit(0)
        
        # Strategy 2: Try sending SIGTERM and wait
        logger.info("Direct report generation failed, trying SIGTERM...")
        os.kill(os.getpid(), signal.SIGTERM)
        
        # Wait for signal handler with periodic checks
        start_time = time.time()
        while time.time() - start_time < self.shutdown_timeout:
            time.sleep(1)
            # Check if we're still running
            logger.debug(f"Waiting for shutdown... ({time.time() - start_time:.0f}s)")
        
        # Strategy 3: Try SIGINT (Ctrl+C) which might interrupt differently
        logger.warning("SIGTERM did not cause exit, trying SIGINT...")
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(5)
        
        # Strategy 4: Force exit
        logger.error("Graceful shutdown failed, forcing exit...")
        os._exit(137)
    
    def _monitor_loop(self):
        """Background thread that monitors memory usage."""
        logger.debug("Memory monitor thread started")
        
        while not self._stop_event.is_set():
            try:
                current_time = time.time()
                
                # Update adaptive limit periodically
                if self.adaptive and (current_time - self._last_limit_update) >= self._limit_update_interval:
                    self._update_adaptive_limit()
                    self._last_limit_update = current_time
                
                current_bytes = self.get_memory_usage_bytes()
                current_mb = current_bytes / (1024 * 1024)
                
                with self._lock:
                    self._current_memory_mb = current_mb
                
                # Log memory usage periodically (every ~30 seconds)
                if int(current_time) % 30 < self.check_interval:
                    if self.adaptive:
                        active_count = self._registry.count_active_processes() if self._registry else 1
                        logger.debug(f"Memory usage: {current_mb:.1f}MB / {self.limit_mb:.1f}MB "
                                   f"({current_bytes / self.limit_bytes * 100:.1f}%) "
                                   f"[{active_count} active processes]")
                    else:
                        logger.debug(f"Memory usage: {current_mb:.1f}MB / {self.limit_mb:.1f}MB "
                                   f"({current_bytes / self.limit_bytes * 100:.1f}%)")
                
                if current_bytes >= self.threshold_bytes:
                    with self._lock:
                        self._limit_exceeded = True
                    
                    if self.adaptive:
                        active_count = self._registry.count_active_processes() if self._registry else 1
                        logger.warning(f"Memory limit threshold reached: {current_mb:.1f}MB / {self.limit_mb:.1f}MB "
                                      f"[{active_count} active processes, pool={self.total_memory_gb:.1f}GB]")
                    else:
                        logger.warning(f"Memory limit threshold reached: {current_mb:.1f}MB / {self.limit_mb:.1f}MB")
                    
                    # Call callback if provided
                    if self.callback:
                        try:
                            self.callback()
                        except Exception as e:
                            logger.error(f"Error in memory limit callback: {e}")
                    
                    # Attempt graceful shutdown
                    if self.auto_signal:
                        self._try_graceful_shutdown()
                    
                    break
                    
            except Exception as e:
                logger.error(f"Error in memory monitor: {e}")
            
            self._stop_event.wait(self.check_interval)
        
        logger.debug("Memory monitor thread stopped")
    
    def start(self):
        """Start the memory monitoring thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("Memory monitor already running")
            return
        
        self._stop_event.clear()
        self._limit_exceeded = False
        self._shutdown_in_progress = False
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("Memory monitor started")
    
    def stop(self):
        """Stop the memory monitoring thread."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        logger.info("Memory monitor stopped")
    
    def check_and_raise(self):
        """
        Check memory and raise MemoryLimitExceeded if limit exceeded.
        
        Call this periodically in your main loop to get an exception
        that you can catch and handle gracefully.
        """
        if self.limit_exceeded:
            raise MemoryLimitExceeded(self.current_memory_mb, self.limit_mb)


# Global monitor instance for easy access
_global_monitor: Optional[MemoryMonitor] = None


def setup_memory_limit(
    limit_gb: Optional[float] = None, 
    shutdown_timeout: float = 30.0,
    **kwargs
) -> MemoryMonitor:
    """
    Set up global memory monitoring with a fixed limit.
    
    Args:
        limit_gb: Memory limit in gigabytes (default: 100GB)
        shutdown_timeout: Seconds to wait for graceful shutdown (default: 30s)
        **kwargs: Additional arguments passed to MemoryMonitor
    
    Returns:
        The MemoryMonitor instance
    """
    global _global_monitor
    if _global_monitor is not None:
        _global_monitor.stop()
    
    _global_monitor = MemoryMonitor(
        limit_gb=limit_gb if limit_gb is not None else 100.0, 
        adaptive=False,
        shutdown_timeout=shutdown_timeout,
        **kwargs
    )
    _global_monitor.start()
    return _global_monitor


def setup_adaptive_memory_limit(
    total_memory_gb: Optional[float] = None,
    min_limit_gb: float = 5.0,
    max_limit_gb: Optional[float] = None,
    shutdown_timeout: float = 30.0,
    **kwargs
) -> MemoryMonitor:
    """
    Set up global memory monitoring with adaptive limits.
    
    The memory limit is dynamically calculated as:
        limit = total_memory_gb / active_processes
    
    As processes terminate, surviving processes automatically get
    a larger share of the memory pool.
    
    Args:
        total_memory_gb: Total memory pool to share among processes.
                        If None, uses 90% of system memory.
        min_limit_gb: Minimum limit per process (default: 5GB)
        max_limit_gb: Maximum limit per process (default: None = no max)
        shutdown_timeout: Seconds to wait for graceful shutdown (default: 30s)
        **kwargs: Additional arguments passed to MemoryMonitor
    
    Returns:
        The MemoryMonitor instance
        
    Example:
        # Share 900GB among all running processes
        setup_adaptive_memory_limit(total_memory_gb=900, min_limit_gb=10)
        
        # With 100 processes: each gets 9GB
        # With 50 processes: each gets 18GB
        # With 10 processes: each gets 90GB
    """
    global _global_monitor
    if _global_monitor is not None:
        _global_monitor.stop()
    
    _global_monitor = MemoryMonitor(
        adaptive=True,
        total_memory_gb=total_memory_gb,
        min_limit_gb=min_limit_gb,
        max_limit_gb=max_limit_gb,
        shutdown_timeout=shutdown_timeout,
        **kwargs
    )
    _global_monitor.start()
    return _global_monitor


def get_memory_monitor() -> Optional[MemoryMonitor]:
    """Get the global memory monitor instance."""
    return _global_monitor


def check_memory_limit():
    """
    Check if global memory limit is exceeded and raise exception if so.
    
    Call this in your exploration loop to enable graceful handling.
    """
    if _global_monitor is not None:
        _global_monitor.check_and_raise()


def set_resource_limits(limit_gb: float = 100.0):
    """
    Set hard resource limits using the resource module.
    
    This provides a secondary safety net - Python will raise MemoryError
    when allocation fails due to these limits.
    
    Note: This sets virtual memory limit (RLIMIT_AS), which may be
    triggered before actual RSS reaches the limit due to memory mapping.
    
    Args:
        limit_gb: Memory limit in gigabytes
    """
    limit_bytes = int(limit_gb * 1024 * 1024 * 1024)
    
    try:
        # Set soft and hard limits for address space
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        logger.info(f"Current RLIMIT_AS: soft={soft}, hard={hard}")
        
        # Set new limits (soft limit triggers MemoryError, hard is absolute max)
        new_soft = limit_bytes
        new_hard = limit_bytes
        resource.setrlimit(resource.RLIMIT_AS, (new_soft, new_hard))
        
        logger.info(f"Set RLIMIT_AS to {limit_gb}GB")
    except Exception as e:
        logger.warning(f"Failed to set resource limits: {e}")
