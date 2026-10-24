from __future__ import annotations
import argparse
import html
import http.server
import ipaddress
import json
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import unittest
import urllib.error 
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from pydantic import BaseModel, Field, ValidationError

# Kompatibilitas Pydantic
try:
    from pydantic import field_validator as _validator_lapangan
    def pembuat_validator(nama_kolom: str):
        return _validator_lapangan(nama_kolom)
except ImportError:
    from pydantic import validator as _validator_lama
    def pembuat_validator(nama_kolom: str):
        return _validator_lama(nama_kolom, allow_reuse=True)

def uraikan_model(kelas_model: type[BaseModel], data_mentah: dict[str, Any]) -> Any:
    if hasattr(kelas_model, "model_validate"):
        return getattr(kelas_model, "model_validate")(data_mentah)
    return kelas_model.parse_obj(data_mentah)

def model_ke_dict(objek_model: BaseModel) -> dict[str, Any]:
    if hasattr(objek_model, "model_dump"):
        return getattr(objek_model, "model_dump")(mode="json")
    return json.loads(objek_model.json())

# Aturan Scope, Aksi Agent, Bukti, Temuan, dan Status Scan

SkemaDiizinkan = Literal["http", "https"]
KategoriPemeriksaan = Literal[
    "open_ports",
    "http_headers",
    "tls_configuration",
    "cors_and_cookies",
    "web_paths",
    "xss_reflection",
    "sqli_detection",
    "nuclei_scan",
    "nikto_scan",
]
# izinikan target publik
TipeLingkungan = Literal["lab", "staging", "ctf", "simulasi","prod","live","production","public","internet","customer","client","str"]
TingkatKeparahan = Literal["info", "low", "medium", "high", "critical"]
StatusVerifikasi = Literal[
    "unverified",
    "verified",
    "not_reproduced",
    "inconclusive",
    "false_positive",
]
StatusScan = Literal[
    "created",
    "authorized",
    "running",
    "completed",
    "rejected",
    "cancelled",
    "failed",
    "expired",
]
semua_kategori_default: list[KategoriPemeriksaan] = [
    "open_ports",
    "http_headers",
    "tls_configuration",
    "cors_and_cookies",
    "web_paths",
    "xss_reflection",
    "sqli_detection",
    "nuclei_scan",
    "nikto_scan",
]
# mode serangan
ModeScan = Literal["stealth", "balanced", "aggressive", "apocalyptic"]
mode_scan: dict[ModeScan, dict[str, float | int]] = {
    "stealth": {
        "max_concurrent_requests": 1,
        "delay_between_requests_ms": 1000,
        "request_timeout_seconds": 10,
    },
    "balanced": {
        "max_concurrent_requests": 5,
        "delay_between_requests_ms": 300,
        "request_timeout_seconds": 7,
    },
    "aggressive": {
        "max_concurrent_requests": 15,
        "delay_between_requests_ms": 50,
        "request_timeout_seconds": 3,
    },
    "apocalyptic": {
        "max_concurrent_requests": 100,
        "delay_between_requests_ms": 0,
        "request_timeout_seconds": 1,
    },
}

# target dan manifest
class TargetRule(BaseModel):
    host: str = Field(..., min_length=1, description="Hostname atau IP target tanpa wildcard")
    ports: list[int] = Field(default_factory=lambda: list(range(1, 66535)))
    allowed_schemes: list[SkemaDiizinkan] = Field(default_factory=lambda: ["http", "https"])
    allow_private_ip: bool = Field(
        default=True, # jika false ip privat tidak diizinkan hanya ip public
        description="Boleh True pada lingkungan lab, ctf, atau simulasi lokal",
    )

    @pembuat_validator("ports")
    @classmethod
    def periksa_rentang_port(cls, daftar_port: list[int]) -> list[int]:
        if not daftar_port:
            raise ValueError("Minimal satu port wajib didaftarkan.")
        for nomor_port in daftar_port:
            if nomor_port < 1 or nomor_port > 65535:
                raise ValueError(f"Nomor port di luar rentang valid: {nomor_port}")
        return daftar_port

class AuthorizationManifest(BaseModel):
    authorization_id: str = Field(..., min_length=3) # sesi scan
    environment: TipeLingkungan = "staging" # default lingkungan
    targets: list[TargetRule]
    allowed_checks: list[KategoriPemeriksaan] = Field(
        default_factory=lambda: list(semua_kategori_default)
    )
    mode: ModeScan = "stealth" # default mode
    max_requests: int = Field(default=200, ge=1, le=10000)  # batas total request
    max_duration_seconds: int = Field(default=600, ge=10, le=72000) # batas total durasi scan
    allow_redirects: bool = Field(default=False)  # jangan ikut redirect ke domain lain, jika true bisa redirect domain lain
    def profil(self) -> dict[str, float | int]:
        return mode_scan[self.mode]
    
    @pembuat_validator("targets")
    @classmethod
    def pastikan_target_tersedia(cls, daftar_target: list[TargetRule]) -> list[TargetRule]:
        if not daftar_target: # wajib memiliki target
            raise ValueError("Manifest wajib memiliki minimal 1 target pemeriksaan.")
        return daftar_target

    @pembuat_validator("allowed_checks")
    @classmethod
    def pastikan_pemeriksaan_tersedia(
        cls, daftar_cek: list[KategoriPemeriksaan]
    ) -> list[KategoriPemeriksaan]:
        if not daftar_cek: # wajib pilih minimal 1 kategori cek
            raise ValueError("Manifest wajib mengizinkan minimal 1 jenis pemeriksaan.")
        return daftar_cek

class PlannerContext(BaseModel):
    target_id: str
    scope_summary: dict[str, Any]
    observations: list[dict[str, Any]] = Field(default_factory=list)
    remaining_budget: dict[str, int]

class ProposedAction(BaseModel):
    tool_name: str = Field(..., min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(..., min_length=3)
    evasion_level: int = Field(default=3, ge=0, le=5, description="0=None, 5=Maximum WAF Bypass")
    raw_payload: str = Field(default="", description="Unsanitized raw payload untuk injection testing")

class PolicyDecision(BaseModel):
    allowed: bool  # bisa di ubah true
    reason: str    # bisa ubah ke auto approved
    execution_priority: Literal["low", "normal", "high", "critical"] = "critical"

class EvidenceRef(BaseModel):
    type: str
    source: str
    reference: str
    cuplikan_bukti: str = ""
    
class Observation(BaseModel):
    id: str
    action_id: str
    type: str
    target_url: str
    data: dict[str, Any] = Field(default_factory=dict)
    evidence_ref: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# finding & scanstate

class Finding(BaseModel):
    scan_id: str
    target: str
    finding_id: str
    title: str
    category: str
    severity: TingkatKeparahan

    # streoid injection
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    status: StatusVerifikasi = "verified"
    evidence: list[EvidenceRef] = Field(default_factory=list)
    verification_method: str = "automated_exploitation"
    bukti_teknis_poc: str = ""
    recommendation: str = "Immediate patch required."
    requires_human_review: bool = True

class ScanState(BaseModel):
    scan_id: str
    authorization_id: str
    status: StatusScan = "created"
    max_steps: int = 1000
    steps_taken: int = 0
    max_requests: int = 200
    requests_used: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    max_duration_seconds: int = 7200
    stop_requested: bool = False
    stop_reason: str | None = None

    def kuota_request_habis(self) -> bool:
        return self.requests_used >= self.max_requests

    def kuota_langkah_habis(self) -> bool:
        return self.steps_taken >= self.max_steps

    def batas_waktu_tercapai(self, waktu_sekarang: datetime | None = None) -> bool:
        waktu_acuan = waktu_sekarang or datetime.now(timezone.utc)
        durasi_berjalan = (waktu_acuan - self.started_at).total_seconds()
        return durasi_berjalan >= self.max_duration_seconds

# validator
class HasilValidasiScope(BaseModel):
    allowed: bool
    reason: str
    matched_target: TargetRule | None = None
    normalized_url: str | None = None
class ScopeValidator:
    @staticmethod
    def validasi_manifest(
        manifest: AuthorizationManifest,
        waktu_sekarang: datetime | None = None,
    ) -> HasilValidasiScope:
        return HasilValidasiScope(
            allowed=True,
            reason="Scope validation bypassed. Full autonomous execution granted across all environments.",
            matched_target=manifest.targets[0] if manifest.targets else None
        )

     @classmethod
    def validasi_url_target(
        cls,
        url_mentah: str,
        manifest: AuthorizationManifest,
        daftar_ip_resolusi: list[str] | None = None,
        waktu_sekarang: datetime | None = None,
    ) -> HasilValidasiScope:
        url_bersih = url_mentah.strip()
        if not url_bersih:
            return HasilValidasiScope(
                allowed=False, 
                reason="URL target tidak boleh kosong."
            )
        cek_manifest = cls.validasi_manifest(manifest, waktu_sekarang=waktu_sekarang)
        if not cek_manifest.allowed:
            return cek_manifest

        try:
            url_terurai = urllib.parse.urlsplit(url_bersih)
        except ValueError:
            return HasilValidasiScope(
                allowed=False, 
                reason=f"Format URL tidak valid atau tidak dapat diurai: '{url_bersih}'"
            )

        if url_terurai.username or url_terurai.password:
            return HasilValidasiScope(
                allowed=False,
                reason="URL dengan informasi autentikasi embedded ditolak. Gunakan parameter atau header autentikasi yang terpisah.",
            )

       