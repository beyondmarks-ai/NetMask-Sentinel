"""Packet capture and flow assembly isolated from Flask request handling."""

from __future__ import annotations

import queue
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from scapy.sendrecv import sniff

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

FlowCallback = Callable[[list[object]], None]


def packet_to_info(packet: Any) -> PacketInfo:
    info = PacketInfo()
    info.setDest(packet)
    info.setSrc(packet)
    info.setSrcPort(packet)
    info.setDestPort(packet)
    info.setProtocol(packet)
    info.setTimestamp(packet)
    info.setPSHFlag(packet)
    info.setFINFlag(packet)
    info.setSYNFlag(packet)
    info.setACKFlag(packet)
    info.setURGFlag(packet)
    info.setRSTFlag(packet)
    info.setPayloadBytes(packet)
    info.setHeaderBytes(packet)
    info.setPacketSize(packet)
    info.setWinBytes(packet)
    info.setFwdID()
    info.setBwdID()
    return info


class FlowTracker:
    """Builds bidirectional flows and emits their canonical 48-value records."""

    def __init__(self, on_flow: FlowCallback, *, timeout_seconds: int = 120) -> None:
        self.on_flow = on_flow
        self.timeout_seconds = timeout_seconds
        self.current: dict[str, Flow] = {}
        self.packet_count = 0
        self.invalid_packet_count = 0
        self.completed_flow_count = 0
        self._lock = threading.RLock()

    def handle_packet(self, packet: Any) -> None:
        try:
            info = packet_to_info(packet)
        except (AttributeError, IndexError, TypeError, ValueError, OSError):
            self.invalid_packet_count += 1
            return

        completed: list[list[object]] = []
        with self._lock:
            self.packet_count += 1
            fwd_id = info.getFwdID()
            bwd_id = info.getBwdID()
            flow_id = fwd_id if fwd_id in self.current else bwd_id if bwd_id in self.current else None

            if flow_id is None:
                self.current[fwd_id] = Flow(info)
                return

            flow = self.current[flow_id]
            elapsed = float(info.getTimestamp() - flow.getFlowLastSeen())
            if elapsed > self.timeout_seconds:
                completed.append(flow.terminated())
                del self.current[flow_id]
                self.current[fwd_id] = Flow(info)
            else:
                direction = "fwd" if flow_id == fwd_id else "bwd"
                flow.new(info, direction)
                if info.getFINFlag() or info.getRSTFlag():
                    completed.append(flow.terminated())
                    del self.current[flow_id]

        for record in completed:
            self.completed_flow_count += 1
            self.on_flow(record)

    def expire_stale(self, *, now: float | None = None) -> int:
        current_time = now if now is not None else time.time()
        completed: list[list[object]] = []
        with self._lock:
            stale_ids = [
                flow_id
                for flow_id, flow in self.current.items()
                if current_time - float(flow.getFlowLastSeen()) > self.timeout_seconds
            ]
            for flow_id in stale_ids:
                completed.append(self.current.pop(flow_id).terminated())
        for record in completed:
            self.completed_flow_count += 1
            self.on_flow(record)
        return len(completed)

    def flush(self) -> int:
        completed: list[list[object]] = []
        with self._lock:
            for flow in self.current.values():
                completed.append(flow.terminated())
            self.current.clear()
        for record in completed:
            self.completed_flow_count += 1
            self.on_flow(record)
        return len(completed)

    def health(self) -> dict[str, int]:
        with self._lock:
            return {
                "active_flows": len(self.current),
                "packets_seen": self.packet_count,
                "invalid_packets": self.invalid_packet_count,
                "completed_flows": self.completed_flow_count,
            }


class CaptureService:
    """Supervised capture and detection workers with a bounded flow queue."""

    def __init__(
        self,
        on_flow: FlowCallback,
        *,
        interface: str | None = None,
        packet_filter: str = "ip and (tcp or udp)",
        flow_timeout_seconds: int = 120,
        queue_size: int = 10_000,
    ) -> None:
        self.on_flow = on_flow
        self.interface = interface
        self.packet_filter = packet_filter
        self.tracker = FlowTracker(self._enqueue_flow, timeout_seconds=flow_timeout_seconds)
        self._queue: queue.Queue[list[object]] = queue.Queue(maxsize=queue_size)
        self._stop = threading.Event()
        self._capture_thread: threading.Thread | None = None
        self._worker_thread: threading.Thread | None = None
        self._started_at: datetime | None = None
        self._last_packet_at: datetime | None = None
        self._last_flow_at: datetime | None = None
        self._last_error: str | None = None
        self._dropped_flows = 0
        self._lock = threading.RLock()

    def _enqueue_flow(self, record: list[object]) -> None:
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            with self._lock:
                self._dropped_flows += 1
                self._last_error = "Detection queue is full; flow dropped"

    def _capture_loop(self) -> None:
        while not self._stop.is_set():
            try:
                sniff(
                    prn=self._handle_packet,
                    store=False,
                    timeout=1,
                    iface=self.interface,
                    filter=self.packet_filter or None,
                )
                self.tracker.expire_stale()
            except Exception as exc:  # Scapy/provider failures must be observable, not fatal.
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"
                self._stop.wait(2)

    def _handle_packet(self, packet: Any) -> None:
        with self._lock:
            self._last_packet_at = datetime.now(timezone.utc)
        self.tracker.handle_packet(packet)

    def _worker_loop(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                record = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.on_flow(record)
                with self._lock:
                    self._last_flow_at = datetime.now(timezone.utc)
            except Exception as exc:
                with self._lock:
                    self._last_error = f"Detection worker: {type(exc).__name__}: {exc}"
            finally:
                self._queue.task_done()

    def start(self) -> bool:
        with self._lock:
            if self.running:
                return False
            self._stop.clear()
            self._started_at = datetime.now(timezone.utc)
            self._last_error = None
            self._capture_thread = threading.Thread(
                target=self._capture_loop, name="netmask-capture", daemon=True
            )
            self._worker_thread = threading.Thread(
                target=self._worker_loop, name="netmask-detection", daemon=True
            )
            self._worker_thread.start()
            self._capture_thread.start()
            return True

    def stop(self, *, flush: bool = True, timeout: float = 5.0) -> None:
        self._stop.set()
        if flush:
            self.tracker.flush()
        for thread in (self._capture_thread, self._worker_thread):
            if thread and thread.is_alive():
                thread.join(timeout=timeout)

    @property
    def running(self) -> bool:
        return bool(self._capture_thread and self._capture_thread.is_alive() and not self._stop.is_set())

    def health(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.running,
                "interface": self.interface or "default",
                "filter": self.packet_filter,
                "queue_depth": self._queue.qsize(),
                "dropped_flows": self._dropped_flows,
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "last_packet_at": self._last_packet_at.isoformat() if self._last_packet_at else None,
                "last_flow_at": self._last_flow_at.isoformat() if self._last_flow_at else None,
                "last_error": self._last_error,
                **self.tracker.health(),
            }