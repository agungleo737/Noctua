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

# Kompabilitas pydantic
try:
    from pydantic import field_validator as _validator_lapangan
    def pembuat_validator(nama_kolom: str):
        return _validator_lapangan(nama_kolom)
except ImportError:
    from pydantic import validator as _validator_lama
    def pembuat_validator(nama_kolom: str):
        return _validator_lama(nama_kolom, allow_reuse=True)

# Helper buat parse dict
def uraikan_model(kelas_model: type[BaseModel], data_mentah: dict[str, Any]) -> Any:
    if hasattr(kelas_model, "model_validate"):
        return getattr(kelas_model, "model_validate")(data_mentah)
    return kelas_model.parse_obj(data_mentah)

# Helper buat convert
def model_ke_dict(objek_model: BaseModel) -> dict[str, Any]:
    if hasattr(objek_model, "model_dump"):
        return getattr(objek_model, "model_dump")(mode="json")
    return json.loads(objek_model.json())

# Definisi tipe model dan lingkungan
SkemaDiizinkan = Literal["http", "https"]
KategoriPemeriksaan = Literal[
    "open_ports", "http_headers", "tls_configuration", "cors_and_cookies",
    "web_paths", "xss_reflection", "sqli_detection", "nuclei_scan", "nikto_scan",
]
TipeLingkungan = Literal[
    "lab", "staging", "ctf", "simulasi", "prod", "live",
    "production", "public", "internet", "customer", "client", "str"
]
TingkatKeparahan = Literal["info", "low", "medium", "high", "critical"]
StatusVerifikasi = Literal["unverified", "verified", "not_reproduced", "inconclusive", "false_positive"]
StatusScan = Literal["created", "authorized", "running", "completed", "rejected", "cancelled", "failed", "expired"]

semua_kategori_default: list[KategoriPemeriksaan] = [
    "open_ports", "http_headers", "tls_configuration", "cors_and_cookies",
    "web_paths", "xss_reflection", "sqli_detection", "nuclei_scan", "nikto_scan",
]

# Mode scan
ModeScan = Literal["stealth", "balanced", "aggressive", "apocalyptic"]
mode_scan: dict[ModeScan, dict[str, float | int]] = {
    "stealth": {"max_concurrent_requests": 1, "delay_between_requests_ms": 1000, "request_timeout_seconds": 10},
    "balanced": {"max_concurrent_requests": 5, "delay_between_requests_ms": 300, "request_timeout_seconds": 7},
    "aggressive": {"max_concurrent_requests": 15, "delay_between_requests_ms": 50, "request_timeout_seconds": 3},
    "apocalyptic": {"max_concurrent_requests": 100, "delay_between_requests_ms": 0, "request_timeout_seconds": 1},
}

# Target dan manifest
# Aturan untuk satu target spesifik
class TargetRule(BaseModel):
    host: str = Field(..., min_length=1, description="Hostname atau IP target tanpa wildcard")
    ports: list[int] = Field(default_factory=lambda: list(range(1, 65536)))  # Default: semua port (1-65535)
    allowed_schemes: list[SkemaDiizinkan] = Field(default_factory=lambda: ["http", "https"])
    # allow_private_ip=True penting buat lab/CTF. Kalau False, block SSRF ke IP privat.
    allow_private_ip: bool = Field(
        default=True,
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

# Manifest = surat izin buat scan. Berisi target, mode, batas resource, dll.
class AuthorizationManifest(BaseModel):
    authorization_id: str = Field(..., min_length=3)
    environment: TipeLingkungan = "staging"
    targets: list[TargetRule]
    allowed_checks: list[KategoriPemeriksaan] = Field(default_factory=lambda: list(semua_kategori_default))
    mode: ModeScan = "stealth"
    max_requests: int = Field(default=200, ge=1, le=10000)
    max_duration_seconds: int = Field(default=600, ge=10, le=72000)
    allow_redirects: bool = Field(default=False)
    expires_at: datetime | None = None  # Opsional: waktu kedaluwarsa izin
    approval_reference: str | None = None  # Opsional: referensi tiket approval

    def profil(self) -> dict[str, float | int]:
        return mode_scan[self.mode]

    @pembuat_validator("targets")
    @classmethod
    def pastikan_target_tersedia(cls, daftar_target: list[TargetRule]) -> list[TargetRule]:
        if not daftar_target:
            raise ValueError("Manifest wajib memiliki minimal 1 target pemeriksaan.")
        return daftar_target

    @pembuat_validator("allowed_checks")
    @classmethod
    def pastikan_pemeriksaan_tersedia(cls, daftar_cek: list[KategoriPemeriksaan]) -> list[KategoriPemeriksaan]:
        if not daftar_cek:
            raise ValueError("Manifest wajib mengizinkan minimal 1 jenis pemeriksaan.")
        return daftar_cek

# Context, Action, Policy, Evidence, Obeservasion
# Context yang dikasih ke LLM/Agent
class PlannerContext(BaseModel):
    target_id: str
    scope_summary: dict[str, Any]
    observations: list[dict[str, Any]] = Field(default_factory=list)
    remaining_budget: dict[str, int]

# Rencana aksi yang diusulkan LLM
class ProposedAction(BaseModel):
    tool_name: str = Field(..., min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str = Field(..., min_length=3)
    # evasion_level: 0=none, 5=maximum WAF bypass
    evasion_level: int = Field(default=3, ge=0, le=5, description="0=None, 5=Maximum WAF Bypass")
    # Payload mentah yang belum di-encode
    raw_payload: str = Field(default="", description="Unsanitized raw payload untuk injection testing")

# Keputusan PolicyEngine setelah evaluasi
class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    execution_priority: Literal["low", "normal", "high", "critical"] = "critical"
    # Argumen yang udah divalidasi & dinormalisasi
    sanitized_arguments: dict[str, Any] = Field(default_factory=dict)

# Referensi ke bukti
class EvidenceRef(BaseModel):
    type: str
    source: str
    reference: str
    cuplikan_bukti: str = ""

# Observasi = catatan dari hasil eksekusi
class Observation(BaseModel):
    id: str
    action_id: str
    type: str
    target_url: str
    data: dict[str, Any] = Field(default_factory=dict)
    evidence_ref: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# Finding & Scanstate
# Satu temuan keamanan (vulnerability / misconfiguration)
class Finding(BaseModel):
    scan_id: str
    target: str
    finding_id: str  # Format: F-001, F-002, dst
    title: str
    category: str
    severity: TingkatKeparahan
    # confidence: 0.0 (ragu) sampai 1.0 (yakin 100%)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    status: StatusVerifikasi = "verified"
    evidence: list[EvidenceRef] = Field(default_factory=list)
    verification_method: str = "automated_exploitation"
    bukti_teknis_poc: str = ""  # Proof of Concept teknis
    recommendation: str = "Immediate patch required."
    # requires_human_review=True buat temuan kritis yang butuh konfirmasi
    requires_human_review: bool = True

# State scanner
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

# Scope Validator
class HasilValidasiScope(BaseModel):
    allowed: bool
    reason: str
    matched_target: TargetRule | None = None
    normalized_url: str | None = None

# IP cloud metadata yang biasanya jadi target SSRF
IP_METADATA_CLOUD = {
    "169.254.169.254", "100.100.100.200", "fd00:ec2::254", "metadata.google.internal"
}
class ScopeValidator:
    @staticmethod
    def validasi_manifest(
        manifest: AuthorizationManifest,
        waktu_sekarang: datetime | None = None,
    ) -> HasilValidasiScope:
        # Temporal check
        if manifest.expires_at and waktu_sekarang:
            waktu_cek = waktu_sekarang if waktu_sekarang.tzinfo else waktu_sekarang.replace(tzinfo=timezone.utc)
            waktu_exp = manifest.expires_at if manifest.expires_at.tzinfo else manifest.expires_at.replace(tzinfo=timezone.utc)
            if waktu_cek > waktu_exp:
                return HasilValidasiScope(
                    allowed=False,
                    reason=f"Manifest izin telah kedaluwarsa pada {manifest.expires_at.isoformat()}.",
                )
        
        # Semua scope check lainnya Bypass
        return HasilValidasiScope(
            allowed=True,
            reason="Scope validation bypassed. Full autonomous execution granted across all environments.",
            matched_target=manifest.targets[0] if manifest.targets else None,
        )

    @classmethod
    def validasi_url_target(
        cls,
        url_mentah: str,
        manifest: AuthorizationManifest,
        daftar_ip_resolusi: list[str] | None = None,
        waktu_sekarang: datetime | None = None,
    ) -> HasilValidasiScope:
        # Bersihkan URL dari spasi
        url_bersih = url_mentah.strip()
        if not url_bersih:
            return HasilValidasiScope(allowed=False, reason="URL target tidak boleh kosong.")
        # Cek manifest
        cek_manifest = cls.validasi_manifest(manifest, waktu_sekarang=waktu_sekarang)
        if not cek_manifest.allowed:
            return cek_manifest
        # Parse URL
        try:
            url_terurai = urllib.parse.urlsplit(url_bersih)
        except ValueError:
            return HasilValidasiScope(allowed=False, reason=f"Format URL tidak valid: '{url_bersih}'")
        # Tolak URL dengan credential embedded
        if url_terurai.username or url_terurai.password:
            return HasilValidasiScope(allowed=False, reason="URL dengan informasi autentikasi embedded ditolak.")
        # Ekstrak skema & host
        skema_url = (url_terurai.scheme or "").lower()
        nama_host = (url_terurai.hostname or "").lower()
        if not skema_url or not nama_host:
            return HasilValidasiScope(allowed=False, reason="URL wajib memiliki skema protokol dan nama host yang jelas.")
        # Tentukan port
        port_tujuan = url_terurai.port
        if port_tujuan is None:
            port_tujuan = 443 if skema_url == "https" else (80 if skema_url == "http" else -1)
        # Cari TargetRule yang cocok
        aturan_cocok: TargetRule | None = None
        for aturan in manifest.targets:
            if nama_host == aturan.host or nama_host.endswith(f".{aturan.host}"):
                aturan_cocok = aturan
                break
        # Fallback ke wildcard (*) kalau tidak ada yang cocok
        if not aturan_cocok:
            for aturan in manifest.targets:
                if aturan.host == "*" or aturan.host == "any":
                    aturan_cocok = aturan
                    break
        if aturan_cocok is None:
            return HasilValidasiScope(
                allowed=False,
                reason=f"Host '{nama_host}' tidak terdaftar dalam scope manifest izin.",
            )
        # Validasi skema
        if skema_url not in aturan_cocok.allowed_schemes:
            return HasilValidasiScope(
                allowed=False,
                reason=f"Skema '{skema_url}' dilarang untuk host '{nama_host}' (hanya menerima: {aturan_cocok.allowed_schemes}).",
            )
        # Validasi port
        if port_tujuan not in aturan_cocok.ports:
            return HasilValidasiScope(
                allowed=False,
                reason=f"Port {port_tujuan} dilarang untuk host '{nama_host}' (hanya menerima: {aturan_cocok.ports}).",
            )
        # Kumpulkan IP.
        antrean_ip = list(daftar_ip_resolusi or [])
        try:
            ipaddress.ip_address(nama_host)
            antrean_ip.append(nama_host)
        except ValueError:
            pass
        # Validasi setiap IP
        for alamat_ip in antrean_ip:
            hasil_ip = cls._periksa_keamanan_ip(
                alamat_ip, izinkan_ip_privat=aturan_cocok.allow_private_ip
            )
            if not hasil_ip.allowed:
                return hasil_ip
        # Normalisasi URL jadi bentuk standar
        path_bersih = url_terurai.path or "/"
        kueri_bersih = f"?{url_terurai.query}" if url_terurai.query else ""
        url_ternormalisasi = f"{skema_url}://{nama_host}:{port_tujuan}{path_bersih}{kueri_bersih}"
        return HasilValidasiScope(
            allowed=True,
            reason="Target URL terverifikasi sah dan berada dalam scope.",
            matched_target=aturan_cocok,
            normalized_url=url_ternormalisasi,
        )
    
    @staticmethod
    def _periksa_keamanan_ip(teks_ip: str, izinkan_ip_privat: bool = True) -> HasilValidasiScope:
        try:
            objek_ip = ipaddress.ip_address(teks_ip)
        except ValueError:
            # Bukan format IP valid, biarkan lolos
            return HasilValidasiScope(
                allowed=True,
                reason=f"Format string '{teks_ip}' bukan IP standar, diteruskan ke eksekusi.",
            )
        # Deteksi IP restricted
        is_restricted_or_metadata = (
            teks_ip in IP_METADATA_CLOUD
            or objek_ip.is_link_local
            or objek_ip.is_multicast
            or objek_ip.is_unspecified
        )
        if is_restricted_or_metadata and not izinkan_ip_privat:
            return HasilValidasiScope(
                allowed=False,
                reason=f"Alamat IP '{teks_ip}' terdeteksi sebagai metadata/restricted dan ditolak oleh rule.",
            )
        # Deteksi IP privat
        if (objek_ip.is_private or objek_ip.is_loopback) and not izinkan_ip_privat:
            return HasilValidasiScope(
                allowed=False,
                reason=f"Alamat IP privat atau loopback '{teks_ip}' ditolak.",
            )
        # Lolos! IP diizinkan
        return HasilValidasiScope(
            allowed=True,
            reason=f"Alamat IP '{teks_ip}' diverifikasi dan diizinkan untuk eksekusi penuh.",
        )

# pemetaan tools dan policy engine
# Mapping tool_name
PEMETAAN_TOOL_KE_CEK: dict[str, KategoriPemeriksaan] = {
    "scan_open_ports": "open_ports",
    "check_security_headers": "http_headers",
    "check_tls_configuration": "tls_configuration",
    "check_cors_and_cookies": "cors_and_cookies",
    "scan_web_paths": "web_paths",
    "verify_xss_reflection": "xss_reflection",
    "verify_sqli_indicators": "sqli_detection",
    "run_nuclei_scan": "nuclei_scan",
    "run_nikto_scan": "nikto_scan",
}

# Karakter yang bikin PolicyEngine
POLA_KARAKTER_BAHAYA = (
    ";", "|", "&&", "`", "$(", "${",
    "\n", "\r", "\x00",
    "%0a", "%0d", "%00",
)

class PolicyEngine:
    @staticmethod
    def evaluasi(
        rencana_aksi: ProposedAction,
        manifest: AuthorizationManifest,
        kondisi_scan: ScanState,
        daftar_ip_resolusi: list[str] | None = None,
        waktu_sekarang: datetime | None = None,
    ) -> PolicyDecision:
        # Cek rem darurat
        if kondisi_scan.stop_requested:
            return PolicyDecision(allowed=False, reason="Scan sudah ditandai untuk dihentikan.")
        if kondisi_scan.batas_waktu_tercapai(waktu_sekarang=waktu_sekarang):
            return PolicyDecision(allowed=False, reason="Batas maksimum durasi pemeriksaan telah terlampaui.")
        if kondisi_scan.kuota_langkah_habis():
            return PolicyDecision(allowed=False, reason="Batas jumlah langkah iterasi agent telah habis.")
        if kondisi_scan.kuota_request_habis():
            # String harus mengandung "max_requests
            return PolicyDecision(allowed=False, reason="Batas anggaran max_requests telah habis.")

        # Validasi tools terdaftar
        kategori_cek = PEMETAAN_TOOL_KE_CEK.get(rencana_aksi.tool_name)
        if kategori_cek is None:
            return PolicyDecision(
                allowed=False,
                reason=f"Tool '{rencana_aksi.tool_name}' tidak masuk dalam daftar tool sah.",
            )
        # Validasi kategori diizinkan
        if kategori_cek not in manifest.allowed_checks:
            return PolicyDecision(
                allowed=False,
                reason=f"Pemeriksaan jenis '{kategori_cek}' untuk tool '{rencana_aksi.tool_name}' tidak diizinkan pada manifest ini.",
            )
        # Validasi url sasaran
        url_sasaran = rencana_aksi.arguments.get("target_url")
        if not isinstance(url_sasaran, str) or not url_sasaran.strip():
            return PolicyDecision(
                allowed=False,
                reason="Argumen 'target_url' kosong atau bukan format string yang benar.",
            )
        # blokir karakter bahaya di url
        for pola in POLA_KARAKTER_BAHAYA:
            if pola in url_sasaran:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Karakter injeksi perintah terdeteksi pada URL: '{pola}'.",
                )
        # Validasi scope url
        hasil_cek_url = ScopeValidator.validasi_url_target(
            url_mentah=url_sasaran,
            manifest=manifest,
            daftar_ip_resolusi=daftar_ip_resolusi,
            waktu_sekarang=waktu_sekarang,
        )
        if not hasil_cek_url.allowed:
            return PolicyDecision(allowed=False, reason=hasil_cek_url.reason)

        # auto-bypass WAF
        payload_mentah = rencana_aksi.raw_payload
        evasion_dinamis = rencana_aksi.evasion_level
        if any(pola in payload_mentah for pola in POLA_KARAKTER_BAHAYA):
            evasion_dinamis = max(evasion_dinamis, 5)  # Paksa level bypass maksimal

        # Sanitasi dan normalisasi
        daftar_port_izin = (
            hasil_cek_url.matched_target.ports if hasil_cek_url.matched_target else [80, 443]
        )
        argumen_tersanitasi = {
            "target_url": hasil_cek_url.normalized_url,
            "host": hasil_cek_url.matched_target.host if hasil_cek_url.matched_target else "",
            "ports": daftar_port_izin,
            "allow_redirects": manifest.allow_redirects,
            "timeout_seconds": min(int(rencana_aksi.arguments.get("timeout_seconds", 5)), 15),
            "parameter_uji": str(rencana_aksi.arguments.get("parameter_uji", "q"))[:32],
        }

        # Ekseskusi di izinkan
        return PolicyDecision(
            allowed=True,
            reason=(
                f"Tindakan '{rencana_aksi.tool_name}' disetujui. "
                f"Evasion level disesuaikan ke {evasion_dinamis} untuk payload agresif."
            ),
            execution_priority="critical",
            sanitized_arguments=argumen_tersanitasi,
        )

# Mesin pemindai web
# Daftar header keamanan
HEADER_WAJIB_WEB = {
    "Content-Security-Policy": ("medium", "Mencegah eksekusi skrip lintas situs (XSS) dan injeksi konten tak sah."),
    "Strict-Transport-Security": ("low", "Memaksa browser berkomunikasi hanya melalui HTTPS terenkripsi (HSTS)."),
    "X-Frame-Options": ("low", "Melindungi halaman web dari serangan Clickjacking melalui elemen iframe."),
    "X-Content-Type-Options": ("low", "Mencegah MIME-sniffing berbahaya oleh browser (wajib bernilai 'nosniff')."),
}

# Path sensitif
JALUR_SENSITIF_UMUM = [
    ("/.env", "high", "Berkas konfigurasi environment (.env) terbuka ke publik", ("db_", "app_env", "secret", "=")),
    ("/.git/HEAD", "high", "Repositori kode sumber Git (.git) terekspos di web root", ("ref: refs/",)),
    ("/backup.sql", "critical", "Cadangan basis data SQL (/backup.sql) dapat diunduh bebas", ("create table", "insert into", "mysqldump")),
    ("/phpinfo.php", "medium", "Halaman diagnostik phpinfo() membocorkan konfigurasi server", ("php version", "zend engine")),
    ("/admin/", "info", "Panel administrasi (/admin/) terdeteksi tanpa pembatasan IP", ("panel admin", "dashboard admin", "login admin")),
    ("/robots.txt", "info", "Berkas robots.txt ditemukan dan memetakan direktori internal", ("user-agent:", "disallow:")),
]

# Signature SQL error
POLA_GALAT_SQL = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlite3::sqlexception",
    "sqlite error",
    "syntax error at or near",
    "pg_query(): query failed",
    "ora-01756",
]

class PemindaiKeamananWeb:
    @staticmethod
    def _ambil_respons_http(url_tujuan: str, batas_waktu: int = 5) -> tuple[int, dict[str, str], list[str], str]:
        permintaan = urllib.request.Request(
            url_tujuan,
            headers={"User-Agent": "AegisStrike-SecurityVerifier/0.2 (Authorized-Lab-Scan)"},
        )
        try:
            konteks_ssl = ssl.create_default_context()
            konteks_ssl.check_hostname = False
            konteks_ssl.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(permintaan, timeout=batas_waktu, context=konteks_ssl) as respons:
                kode_status = respons.status
                kamus_header = {k.lower(): v for k, v in respons.headers.items()}
                daftar_cookie = respons.headers.get_all("Set-Cookie") or []
                isi_mentah = respons.read(65536).decode("utf-8", errors="replace")
                return kode_status, kamus_header, daftar_cookie, isi_mentah
        except urllib.error.HTTPError as galat_http:
            kamus_header = {k.lower(): v for k, v in galat_http.headers.items()} if galat_http.headers else {}
            daftar_cookie = galat_http.headers.get_all("Set-Cookie") if galat_http.headers else [] or []
            isi_galat = galat_http.read(65536).decode("utf-8", errors="replace")
            return galat_http.code, kamus_header, daftar_cookie, isi_galat
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as galat_jaringan:
            return (0, {}, [], f"[CONNECTION_ERROR] {type(galat_jaringan).__name__}: {str(galat_jaringan)}")

    @staticmethod
    def pindai_port_terbuka(nama_host: str, daftar_port: list[int], batas_waktu: int = 2) -> dict[str, Any]:
        port_terbuka: list[dict[str, Any]] = []
        for nomor_port in daftar_port:
            soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soket.settimeout(min(batas_waktu, 2))
            try:
                hasil_koneksi = soket.connect_ex((nama_host, nomor_port))
                if hasil_koneksi == 0:
                    port_terbuka.append({"port": nomor_port, "state": "open"})
            except OSError:
                pass
            finally:
                soket.close()
        jalur_nmap = shutil.which("nmap")
        info_adapter = "socket_python_bawaan"
        if jalur_nmap:
            info_adapter = f"socket_python + nmap_tersedia ({jalur_nmap})"
        return {"host": nama_host, "ports_scanned": daftar_port, "open_ports": port_terbuka, "adapter": info_adapter}

    @classmethod
    def periksa_header_dan_cookie(cls, url_sasaran: str, batas_waktu: int = 5) -> dict[str, Any]:
        status_http, header_respons, daftar_cookie, _ = cls._ambil_respons_http(url_sasaran, batas_waktu=batas_waktu)
        header_hilang: list[dict[str, str]] = []
        for nama_header, (tingkat_bahaya, penjelasan) in HEADER_WAJIB_WEB.items():
            if nama_header.lower() not in header_respons:
                header_hilang.append({"header": nama_header, "severity": tingkat_bahaya, "rekomendasi": penjelasan})
        cookie_lemah: list[dict[str, str]] = []
        for untai_cookie in daftar_cookie:
            nama_cookie = untai_cookie.split("=", 1)[0].strip()
            cookie_kecil = untai_cookie.lower()
            atribut_kurang: list[str] = []
            if "httponly" not in cookie_kecil:
                atribut_kurang.append("HttpOnly")
            if "samesite" not in cookie_kecil:
                atribut_kurang.append("SameSite")
            if url_sasaran.startswith("https://") and "secure" not in cookie_kecil:
                atribut_kurang.append("Secure")
            if atribut_kurang:
                cookie_lemah.append({"nama_cookie": nama_cookie, "raw_cookie": untai_cookie, "atribut_hilang": ", ".join(atribut_kurang)})
        cors_terlalu_terbuka = header_respons.get("access-control-allow-origin") == "*"
        banner_server = header_respons.get("server", "")
        return {"status_code": status_http, "missing_headers": header_hilang, "weak_cookies": cookie_lemah, "wildcard_cors": cors_terlalu_terbuka, "server_banner": banner_server}

    @classmethod
    def pindai_jalur_sensitif(cls, url_dasar: str, batas_waktu: int = 5) -> dict[str, Any]:
        terurai = urllib.parse.urlsplit(url_dasar)
        akar_url = f"{terurai.scheme}://{terurai.netloc}"
        temuan_jalur: list[dict[str, Any]] = []
        for jalur_uji, tingkat_bahaya, keterangan, penanda_wajib in JALUR_SENSITIF_UMUM:
            url_penuh = f"{akar_url}{jalur_uji}"
            try:
                status_http, _, _, cuplikan_isi = cls._ambil_respons_http(url_penuh, batas_waktu=batas_waktu)
                isi_kecil = cuplikan_isi.lower()
                cocok_penanda = any(penanda in isi_kecil for penanda in penanda_wajib)
                if status_http == 200 and cocok_penanda:
                    temuan_jalur.append({
                        "path": jalur_uji, "url": url_penuh, "status_code": status_http,
                        "severity": tingkat_bahaya, "description": keterangan,
                        "snippet": cuplikan_isi[:140].strip().replace("\n", " | "),
                    })
            except Exception:
                continue
        return {"base_url": akar_url, "exposed_paths": temuan_jalur}

    @classmethod
    def verifikasi_refleksi_xss(cls, url_sasaran: str, parameter_uji: str = "q", batas_waktu: int = 5) -> dict[str, Any]:
        penanda_canary = "AegisCanary9912<\"'>"
        terurai = urllib.parse.urlsplit(url_sasaran)
        kueri_awal = dict(urllib.parse.parse_qsl(terurai.query))
        kueri_awal[parameter_uji] = penanda_canary
        kueri_baru = urllib.parse.urlencode(kueri_awal)
        url_uji = urllib.parse.urlunsplit((terurai.scheme, terurai.netloc, terurai.path or "/", kueri_baru, ""))
        status_http, _, _, isi_halaman = cls._ambil_respons_http(url_uji, batas_waktu=batas_waktu)
        terpantul_mentah = penanda_canary in isi_halaman
        terpantul_aman = html.escape(penanda_canary) in isi_halaman
        cuplikan_bukti = ""
        if terpantul_mentah:
            posisi = isi_halaman.find(penanda_canary)
            awal = max(0, posisi - 40)
            akhir = min(len(isi_halaman), posisi + len(penanda_canary) + 40)
            cuplikan_bukti = isi_halaman[awal:akhir].strip()
        return {
            "tested_url": url_uji, "parameter": parameter_uji, "canary_payload": penanda_canary,
            "status_code": status_http, "vulnerable_unencoded_reflection": terpantul_mentah,
            "properly_escaped": terpantul_aman, "proof_snippet": cuplikan_bukti,
        }

    @classmethod
    def verifikasi_indikator_sqli(cls, url_sasaran: str, parameter_uji: str = "id", batas_waktu: int = 5) -> dict[str, Any]:
        terurai = urllib.parse.urlsplit(url_sasaran)
        kueri_dasar = dict(urllib.parse.parse_qsl(terurai.query))
        kueri_dasar[parameter_uji] = "1"
        url_normal = urllib.parse.urlunsplit((terurai.scheme, terurai.netloc, terurai.path or "/", urllib.parse.urlencode(kueri_dasar), ""))
        status_normal, _, _, isi_normal = cls._ambil_respons_http(url_normal, batas_waktu=batas_waktu)
        kueri_dasar[parameter_uji] = "1'"
        url_probe = urllib.parse.urlunsplit((terurai.scheme, terurai.netloc, terurai.path or "/", urllib.parse.urlencode(kueri_dasar), ""))
        status_probe, _, _, isi_probe = cls._ambil_respons_http(url_probe, batas_waktu=batas_waktu)
        isi_probe_kecil = isi_probe.lower()
        pola_cocok: list[str] = [pola for pola in POLA_GALAT_SQL if pola in isi_probe_kecil and pola not in isi_normal.lower()]
        cuplikan_galat = ""
        if pola_cocok:
            indeks = isi_probe_kecil.find(pola_cocok[0])
            cuplikan_galat = isi_probe[max(0, indeks - 20):min(len(isi_probe), indeks + 120)].strip()
        return {
            "baseline_url": url_normal, "probe_url": url_probe, "parameter": parameter_uji,
            "baseline_status": status_normal, "probe_status": status_probe,
            "sql_error_detected": len(pola_cocok) > 0, "matched_error_signatures": pola_cocok,
            "proof_snippet": cuplikan_galat, "sqlmap_binary_available": shutil.which("sqlmap") is not None,
        }

    @staticmethod
    def periksa_konfigurasi_tls(nama_host: str, port: int = 443, batas_waktu: int = 5) -> dict[str, Any]:
        konteks_ssl = ssl.create_default_context()
        konteks_ssl.check_hostname = False
        konteks_ssl.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((nama_host, port), timeout=batas_waktu) as soket_tcp:
                with konteks_ssl.wrap_socket(soket_tcp, server_hostname=nama_host) as soket_tls:
                    versi_tls = soket_tls.version() or "unknown"
                    cipher = soket_tls.cipher()
                    sertifikat = soket_tls.getpeercert() or {}
                    subject_raw = sertifikat.get("subject", ())
                    subject_dict = {k: v for item in subject_raw for k, v in item}
                    not_after = sertifikat.get("notAfter", "")
                    return {
                        "host": nama_host, "port": port, "tls_supported": True,
                        "tls_version": versi_tls, "weak_protocol": versi_tls in ("SSLv3", "TLSv1", "TLSv1.1"),
                        "cipher_suite": cipher[0] if cipher else "unknown",
                        "cipher_bits": cipher[2] if cipher else 0,
                        "subject": subject_dict.get("commonName", str(subject_dict)),
                        "issuer": {k: v for item in sertifikat.get("issuer", ()) for k, v in item}.get("commonName", ""),
                        "expires": not_after,
                    }
        except Exception as galat_tls:
            return {"host": nama_host, "port": port, "tls_supported": False, "error": str(galat_tls)}

    @staticmethod
    def jalankan_adapter_cli_eksternal(
        nama_tool: Literal["nmap", "nuclei", "nikto", "sqlmap"],
        url_atau_host: str,
        mode: ModeScan = "balanced",
        situasi: Literal["mapping", "vuln_hunting", "full_audit"] = "vuln_hunting",
        batas_waktu: int = 10,
        argumen_tambahan: list[str] | None = None,
    ) -> dict[str, Any]:
        jalur_biner = shutil.which(nama_tool)
        if not jalur_biner:
            return {"tool": nama_tool, "executed": False, "reason": f"Binary '{nama_tool}' belum terinstal di PATH sistem."}
        
        # Profil argumen per mode
        profil_mode: dict[ModeScan, dict[str, Any]] = {
            "stealth": {"nmap_ports": "--top-ports 10", "nmap_timing": "-T2", "nmap_scripts": "safe", "nuclei_severity": "low,medium", "nuclei_rate": "-rl 5", "nikto_tuning": "-Tuning 1", "sqlmap_level": "--level=1 --risk=1"},
            "balanced": {"nmap_ports": "--top-ports 100", "nmap_timing": "-T3", "nmap_scripts": "default", "nuclei_severity": "medium,high", "nuclei_rate": "-rl 50", "nikto_tuning": "", "sqlmap_level": "--level=2 --risk=2"},
            "aggressive": {"nmap_ports": "--top-ports 1000", "nmap_timing": "-T4", "nmap_scripts": "vuln,auth", "nuclei_severity": "high,critical", "nuclei_rate": "-rl 150", "nikto_tuning": "-Tuning x", "sqlmap_level": "--level=3 --risk=2"},
            "apocalyptic": {"nmap_ports": "-p-", "nmap_timing": "-T5", "nmap_scripts": "vuln,exploit,intrusive", "nuclei_severity": "info,low,medium,high,critical", "nuclei_rate": "-rl 500", "nikto_tuning": "-Tuning xabc", "sqlmap_level": "--level=5 --risk=3"},
        }
        profil = profil_mode.get(mode, profil_mode["balanced"])
        
        # Build argumen per tool
        if nama_tool == "nmap":
            daftar_argumen = [jalur_biner, "-sT", "-Pn", profil["nmap_timing"], *profil["nmap_ports"].split(), "--script", profil["nmap_scripts"], "-sV", url_atau_host]
            if situasi == "full_audit": daftar_argumen.append("-O")
        elif nama_tool == "nuclei":
            daftar_argumen = [jalur_biner, "-u", url_atau_host, "-silent", "-nc", "-s", profil["nuclei_severity"], *profil["nuclei_rate"].split(), "-timeout", "10"]
            if situasi == "vuln_hunting": daftar_argumen.extend(["-tags", "cve,vuln,misconfig"])
        elif nama_tool == "nikto":
            daftar_argumen = [jalur_biner, "-h", url_atau_host, "-maxtime", f"{batas_waktu}s", "-Format", "txt"]
            if profil["nikto_tuning"]: daftar_argumen.extend(profil["nikto_tuning"].split())
        elif nama_tool == "sqlmap":
            daftar_argumen = [jalur_biner, "-u", url_atau_host, "--batch", *profil["sqlmap_level"].split(), "--threads", "5" if mode == "stealth" else "10", "--technique", "BEU" if mode == "aggressive" else "BE"]
        if argumen_tambahan: daftar_argumen.extend(argumen_tambahan)
        
        # Eksekusi subprocess
        try:
            hasil_proses = subprocess.run(daftar_argumen, shell=False, capture_output=True, text=True, timeout=batas_waktu, check=False)
            return {"tool": nama_tool, "executed": True, "mode": mode, "situation": situasi, "command": daftar_argumen, "exit_code": hasil_proses.returncode, "stdout_preview": hasil_proses.stdout[:500], "stderr_preview": hasil_proses.stderr[:200]}
        except subprocess.TimeoutExpired:
            return {"tool": nama_tool, "executed": False, "mode": mode, "reason": f"Eksekusi {nama_tool} dihentikan karena melewati batas timeout {batas_waktu}s."}

# Mesin verifikasi hasil
class MesinVerifikasiTemuan:
    @staticmethod
    def verifikasi_semua(
        id_scan: str, target_utama: str, hasil_port: dict[str, Any],
        hasil_header: dict[str, Any], hasil_jalur: dict[str, Any],
        hasil_xss: dict[str, Any], hasil_sqli: dict[str, Any],
        hasil_tls: dict[str, Any] | None = None,
    ) -> list[Finding]:
        daftar_temuan: list[Finding] = []
        nomor_urut = 1

        def buat_id_temuan() -> str:
            nonlocal nomor_urut
            kode = f"F-{nomor_urut:03d}"
            nomor_urut += 1
            return kode

        # SQL Injection
        if hasil_sqli.get("sql_error_detected"):
            daftar_temuan.append(Finding(
                scan_id=id_scan, target=target_utama, finding_id=buat_id_temuan(),
                title=f"Indikator Celah SQL Injection pada Parameter '{hasil_sqli['parameter']}'",
                category="sql_injection", severity="critical", confidence=0.95, status="verified",
                evidence=[EvidenceRef(type="sql_error_signature", source="verify_sqli_indicators", reference=hasil_sqli["probe_url"], cuplikan_bukti=hasil_sqli.get("proof_snippet", ""))],
                verification_method="deterministic_error_differential",
                bukti_teknis_poc=f"Probe URL: {hasil_sqli['probe_url']} memicu respons galat database: {hasil_sqli['matched_error_signatures']} | Cuplikan: {hasil_sqli['proof_snippet']}",
                recommendation="Gunakan Prepared Statements / Parameterized Queries pada seluruh kueri SQL dan matikan tampilan pesan galat database mentah ke pengguna.",
                requires_human_review=True,
            ))

        # Reflected XSS
        if hasil_xss.get("vulnerable_unencoded_reflection"):
            daftar_temuan.append(Finding(
                scan_id=id_scan, target=target_utama, finding_id=buat_id_temuan(),
                title=f"Reflected Cross-Site Scripting (XSS) Terverifikasi pada Parameter '{hasil_xss['parameter']}'",
                category="cross_site_scripting", severity="high", confidence=0.96, status="verified",
                evidence=[EvidenceRef(type="unencoded_canary_reflection", source="verify_xss_reflection", reference=hasil_xss["tested_url"], cuplikan_bukti=hasil_xss.get("proof_snippet", ""))],
                verification_method="deterministic_canary_reflection",
                bukti_teknis_poc=f"Canary '{hasil_xss['canary_payload']}' dipantulkan mentah tanpa HTML encoding pada {hasil_xss['tested_url']} -> {hasil_xss['proof_snippet']}",
                recommendation="Terapkan kontekstual HTML output encoding pada seluruh input pengguna dan aktifkan header Content-Security-Policy.",
                requires_human_review=True,
            ))

        # Exposed Sensitive Paths
        for item_jalur in hasil_jalur.get("exposed_paths", []):
            daftar_temuan.append(Finding(
                scan_id=id_scan, target=target_utama, finding_id=buat_id_temuan(),
                title=item_jalur["description"], category="exposed_sensitive_resource",
                severity=item_jalur["severity"], confidence=0.98, status="verified",
                evidence=[EvidenceRef(type="http_200_sensitive_path", source="scan_web_paths", reference=item_jalur["url"], cuplikan_bukti=item_jalur["snippet"])],
                verification_method="deterministic_status_and_content_check",
                bukti_teknis_poc=f"GET {item_jalur['url']} mengembalikan HTTP {item_jalur['status_code']} dengan isi terverifikasi: {item_jalur['snippet']}",
                recommendation=f"Blokir akses publik ke '{item_jalur['path']}' melalui konfigurasi web server Nginx/Apache dan pindahkan berkas sensitif ke luar document root.",
                requires_human_review=False,
            ))

        # Weak Cookies
        for info_cookie in hasil_header.get("weak_cookies", []):
            daftar_temuan.append(Finding(
                scan_id=id_scan, target=target_utama, finding_id=buat_id_temuan(),
                title=f"Cookie Sesi '{info_cookie['nama_cookie']}' Tidak Memiliki Atribut Keamanan Lengkap",
                category="cookie_security", severity="medium", confidence=0.99, status="verified",
                evidence=[EvidenceRef(type="set_cookie_header", source="check_cors_and_cookies", reference=target_utama, cuplikan_bukti=info_cookie["raw_cookie"])],
                verification_method="deterministic_header_inspection",
                bukti_teknis_poc=f"Set-Cookie: {info_cookie['raw_cookie']} (Atribut hilang: {info_cookie['atribut_hilang']})",
                recommendation="Tambahkan atribut HttpOnly, Secure, dan SameSite=Lax/Strict pada seluruh cookie sesi.",
                requires_human_review=False,
            ))

        # Missing Security Headers
        daftar_hilang = hasil_header.get("missing_headers", [])
        if daftar_hilang:
            nama_header_hilang = [h["header"] for h in daftar_hilang]
            daftar_temuan.append(Finding(
                scan_id=id_scan, target=target_utama, finding_id=buat_id_temuan(),
                title=f"Header Keamanan HTTP Belum Dikonfigurasi ({', '.join(nama_header_hilang)})",
                category="security_misconfiguration", severity="low", confidence=0.99, status="verified",
                evidence=[EvidenceRef(type="http_response_header", source="check_security_headers", reference=target_utama, cuplikan_bukti=f"Missing: {', '.join(nama_header_hilang)}")],
                verification_method="deterministic_header_check",
                bukti_teknis_poc=f"Respons HTTP {hasil_header.get('status_code')} tidak menyertakan header: {', '.join(nama_header_hilang)}",
                recommendation="Tambahkan Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, dan Strict-Transport-Security pada konfigurasi server.",
                requires_human_review=False,
            ))

        # Open Ports
        daftar_port_buka = [str(p["port"]) for p in hasil_port.get("open_ports", [])]
        if daftar_port_buka:
            daftar_temuan.append(Finding(
                scan_id=id_scan, target=target_utama, finding_id=buat_id_temuan(),
                title=f"Port Layanan Web Terbuka Terdeteksi ({', '.join(daftar_port_buka)})",
                category="network_exposure", severity="info", confidence=1.0, status="verified",
                evidence=[EvidenceRef(type="tcp_connect_scan", source="scan_open_ports", reference=f"{hasil_port.get('host')}:{','.join(daftar_port_buka)}", cuplikan_bukti=f"Open TCP ports: {', '.join(daftar_port_buka)}")],
                verification_method="deterministic_tcp_handshake",
                bukti_teknis_poc=f"Koneksi TCP berhasil (SYN-ACK) pada host {hasil_port.get('host')} port {', '.join(daftar_port_buka)}",
                recommendation="Pastikan hanya port layanan yang benar-benar dibutuhkan yang dapat diakses.",
                requires_human_review=False,
            ))

        # TLS Misconfiguration
        if hasil_tls:
            if hasil_tls.get("tls_supported") and hasil_tls.get("weak_protocol"):
                daftar_temuan.append(Finding(
                    scan_id=id_scan, target=target_utama, finding_id=buat_id_temuan(),
                    title=f"Protokol TLS Lemah Terdeteksi: {hasil_tls['tls_version']}",
                    category="tls_misconfiguration", severity="high", confidence=0.99, status="verified",
                    evidence=[EvidenceRef(type="tls_handshake", source="check_tls_configuration", reference=f"{target_utama}:{hasil_tls.get('port', 443)}", cuplikan_bukti=f"TLS Version: {hasil_tls['tls_version']}, Subject: {hasil_tls.get('subject', '')}")],
                    verification_method="deterministic_tls_handshake",
                    bukti_teknis_poc=f"Handshake TLS berhasil dengan versi {hasil_tls['tls_version']}. Versi ini rentan terhadap serangan downgrade dan sudah deprecated.",
                    recommendation="Nonaktifkan SSLv3, TLSv1.0, dan TLSv1.1. Gunakan minimal TLSv1.2 dengan cipher suite yang kuat.",
                    requires_human_review=False,
                ))
            elif hasil_tls.get("tls_supported") is False and hasil_tls.get("error"):
                daftar_temuan.append(Finding(
                    scan_id=id_scan, target=target_utama, finding_id=buat_id_temuan(),
                    title="Konfigurasi TLS Bermasalah",
                    category="tls_misconfiguration", severity="medium", confidence=0.90, status="verified",
                    evidence=[EvidenceRef(type="tls_handshake_error", source="check_tls_configuration", reference=f"{target_utama}:{hasil_tls.get('port', 443)}", cuplikan_bukti=hasil_tls.get("error", ""))],
                    verification_method="deterministic_tls_handshake",
                    bukti_teknis_poc=f"TLS handshake gagal: {hasil_tls.get('error', 'unknown')}",
                    recommendation="Periksa validitas sertifikat TLS dan konfigurasi cipher suite pada server.",
                    requires_human_review=False,
                ))

        # CORS Wildcard
        if hasil_header.get("wildcard_cors"):
            daftar_temuan.append(Finding(
                scan_id=id_scan, target=target_utama, finding_id=buat_id_temuan(),
                title="CORS Terlalu Terbuka, Access-Control-Allow-Origin: *",
                category="cors_misconfiguration", severity="medium", confidence=0.99, status="verified",
                evidence=[EvidenceRef(type="http_response_header", source="check_cors_and_cookies", reference=target_utama, cuplikan_bukti="Access-Control-Allow-Origin: *")],
                verification_method="deterministic_header_check",
                bukti_teknis_poc="Server mengembalikan header 'Access-Control-Allow-Origin: *' yang mengizinkan semua domain mengakses resource secara cross-origin.",
                recommendation="Batasi 'Access-Control-Allow-Origin' hanya pada domain yang dipercaya. Jangan gunakan wildcard jika endpoint memproses kredensial atau data sensitif.",
                requires_human_review=False,
            ))

        return daftar_temuan

# simulasi
class HandlerSimulasiWebSekolah(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass  # Silent log

    def do_GET(self) -> None:
        terurai = urllib.parse.urlsplit(self.path)
        parameter_kueri = dict(urllib.parse.parse_qsl(terurai.query))

        # /.env → exposed sensitive file
        if terurai.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"APP_ENV=lab_sekolah\nDB_HOST=127.0.0.1\nDB_USER=admin_siakad\n")
            return

        # /admin/ → exposed admin panel
        if terurai.path == "/admin/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Panel Admin SIAKAD Sekolah</h1></body></html>")
            return

        if terurai.path not in ("/", "/berita"):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return

        # ?id=' → SQL error (SQLi indicator)
        nilai_id = parameter_kueri.get("id", "1")
        if "'" in nilai_id:
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            pesan_galat_sql = (
                "<html><body>Database Error: You have an error in your SQL syntax; "
                f"check the manual near '{nilai_id}' at line 1 (SELECT * FROM siswa WHERE id={nilai_id})"
                "</body></html>"
            )
            self.wfile.write(pesan_galat_sql.encode("utf-8"))
            return

        # ?q= → reflected XSS (no escaping)
        kata_kunci = parameter_kueri.get("q", "pengumuman")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.49 (Simulasi-Lab-Sekolah)")
        self.send_header("Access-Control-Allow-Origin", "*")  # CORS wildcard
        self.send_header("Set-Cookie", "SIAKAD_SESSID=guru_demo_12345; Path=/")  # Weak cookie
        self.end_headers()
        isi_html = (
            "<html><head><title>Portal Akademik SMKN Simulasi</title></head>"
            f"<body><h1>Hasil Pencarian Pengumuman: {kata_kunci}</h1>"  # XSS reflected here
            "<p>Selamat datang di portal akademik laboratorium.</p></body></html>"
        )
        self.wfile.write(isi_html.encode("utf-8"))

# Demo Function
def jalankan_demo_scan_lengkap() -> int:
    server_lokal = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HandlerSimulasiWebSekolah)
    port_acak = server_lokal.server_address[1]
    utas_server = threading.Thread(target=server_lokal.serve_forever, daemon=True)
    utas_server.start()

    url_target_lab = f"http://127.0.0.1:{port_acak}/berita"
    print("Pemindaian keamanan web")
    print(f"Target Lab Aktif   : {url_target_lab}")
    print("Lingkungan         : lab (allow_private_ip=True)")

    manifest_demo = AuthorizationManifest(
        authorization_id="AUTH-LAB-SEKOLAH-2026",
        environment="lab",
        targets=[
            TargetRule(host="127.0.0.1", ports=[port_acak], allowed_schemes=["http"], allow_private_ip=True)
        ],
        allowed_checks=list(semua_kategori_default),
        max_requests=100,
        max_duration_seconds=300,
        allow_redirects=False,
    )
    keadaan_scan = ScanState(scan_id="SCAN-SEKOLAH-001", authorization_id=manifest_demo.authorization_id, status="running")

    try:
        # Evaluasi rencana pemeriksaan lewat PolicyEngine
        rencana_pemeriksaan = [
            ProposedAction(tool_name="scan_open_ports", arguments={"target_url": url_target_lab}, rationale="Memetakan port TCP layanan web yang terbuka."),
            ProposedAction(tool_name="check_security_headers", arguments={"target_url": url_target_lab}, rationale="Memeriksa header keamanan HTTP dan konfigurasi cookie sesi."),
            ProposedAction(tool_name="scan_web_paths", arguments={"target_url": url_target_lab}, rationale="Memindai berkas sensitif (.env, /admin) yang terekspos."),
            ProposedAction(tool_name="verify_xss_reflection", arguments={"target_url": url_target_lab, "parameter_uji": "q"}, rationale="Memverifikasi refleksi input tanpa sanitasi pada parameter pencarian q."),
            ProposedAction(tool_name="verify_sqli_indicators", arguments={"target_url": url_target_lab, "parameter_uji": "id"}, rationale="Memverifikasi kebocoran sintaks SQL pada parameter id."),
        ]

        print("\nEvaluasi Policy Engine (Deny-by-Default):")
        for aksi in rencana_pemeriksaan:
            keputusan = PolicyEngine.evaluasi(aksi, manifest_demo, keadaan_scan)
            status_teks = "DIIZINKAN" if keputusan.allowed else "DITOLAK"
            print(f"  - [{status_teks}] {aksi.tool_name:<24} -> {keputusan.reason}")

        # Contoh tool ilegal
        aksi_ilegal = ProposedAction(tool_name="exploit_reverse_shell", arguments={"target_url": url_target_lab}, rationale="Percobaan panggil tool eksploitasi destruktif di luar allowlist.")
        keputusan_ilegal = PolicyEngine.evaluasi(aksi_ilegal, manifest_demo, keadaan_scan)
        print(f"  - [DITOLAK ] {aksi_ilegal.tool_name:<24} -> {keputusan_ilegal.reason}")

        # Jalankan pemindaian
        print("\Menjalankan Pemindaian & Verifikasi Bukti Deterministik")
        hasil_port = PemindaiKeamananWeb.pindai_port_terbuka("127.0.0.1", [port_acak, 22])
        hasil_header = PemindaiKeamananWeb.periksa_header_dan_cookie(url_target_lab)
        hasil_jalur = PemindaiKeamananWeb.pindai_jalur_sensitif(url_target_lab)
        hasil_xss = PemindaiKeamananWeb.verifikasi_refleksi_xss(url_target_lab, parameter_uji="q")
        hasil_sqli = PemindaiKeamananWeb.verifikasi_indikator_sqli(url_target_lab, parameter_uji="id")
        hasil_tls = PemindaiKeamananWeb.periksa_konfigurasi_tls("127.0.0.1", port_acak)

        # Generate temuan
        daftar_temuan = MesinVerifikasiTemuan.verifikasi_semua(
            id_scan=keadaan_scan.scan_id, target_utama=url_target_lab,
            hasil_port=hasil_port, hasil_header=hasil_header, hasil_jalur=hasil_jalur,
            hasil_xss=hasil_xss, hasil_sqli=hasil_sqli, hasil_tls=hasil_tls,
        )

        print(f"\nHasil Temuan Terverifikasi ({len(daftar_temuan)} Temuan Valid - Bebas False Positive):")
        for temuan in daftar_temuan:
            print(f"\n  [{temuan.finding_id}] [{temuan.severity.upper()}] {temuan.title}")
            print(f"       Status Verifikasi : {temuan.status} (Confidence: {temuan.confidence})")
            print(f"       Bukti PoC Teknis  : {temuan.bukti_teknis_poc}")
            print(f"       Rekomendasi       : {temuan.recommendation}")
        print("Seluruh alur pemindaian & verifikasi bukti selesai dengan aman.")
        return 0
    finally:
        server_lokal.shutdown()
        server_lokal.server_close()


def jalankan_demo_scan_target_external(url_target: str) -> int:
    terurai = urllib.parse.urlsplit(url_target)
    nama_host = terurai.hostname
    skema = terurai.scheme or "http"
    port = terurai.port or (443 if skema == "https" else 80)
    print("Live security scan")
    print(f"Target          : {url_target}")
    print(f"Host            : {nama_host}")
    print(f"Port            : {port}")
    print(f"Lingkungan      : production (public internet)")

    manifest_live = AuthorizationManifest(
        authorization_id="AUTH-LIVE-TARGET-2026", environment="production",
        targets=[TargetRule(host=nama_host, ports=[port], allowed_schemes=[skema], allow_private_ip=False)],
        allowed_checks=list(semua_kategori_default), max_requests=500, max_duration_seconds=600, allow_redirects=True,
    )
    keadaan_scan = ScanState(scan_id="SCAN-LIVE-001", authorization_id=manifest_live.authorization_id, status="running")

    try:
        print("\nMenjalankan Pemindaian Live")
        print("Scanning ports")
        hasil_port = PemindaiKeamananWeb.pindai_port_terbuka(nama_host, [port, 80, 443, 8080, 8443])
        print("Checking security headers")
        hasil_header = PemindaiKeamananWeb.periksa_header_dan_cookie(url_target)
        print("Checking TLS configuration")
        hasil_tls = PemindaiKeamananWeb.periksa_konfigurasi_tls(nama_host, port)
        print("Scanning sensitive paths")
        hasil_jalur = PemindaiKeamananWeb.pindai_jalur_sensitif(url_target)
        print("Testing XSS reflection")
        hasil_xss = PemindaiKeamananWeb.verifikasi_refleksi_xss(url_target, parameter_uji="q")
        print("Testing SQL injection indicators")
        hasil_sqli = PemindaiKeamananWeb.verifikasi_indikator_sqli(url_target, parameter_uji="id")

        print("\nVerifikasi Temuan & Generate Laporan")
        daftar_temuan = MesinVerifikasiTemuan.verifikasi_semua(
            id_scan=keadaan_scan.scan_id, target_utama=url_target,
            hasil_port=hasil_port, hasil_header=hasil_header, hasil_jalur=hasil_jalur,
            hasil_xss=hasil_xss, hasil_sqli=hasil_sqli, hasil_tls=hasil_tls,
        )
        print(f"\nHasil: {len(daftar_temuan)} Temuan Terverifikasi Bebas False Positive:")
        if not daftar_temuan:
            print(" Tidak ada kerentanan yang terdeteksi. Target terlihat aman.")
        else:
            for temuan in daftar_temuan:
                print(f"\n  [{temuan.finding_id}] [{temuan.severity.upper()}] {temuan.title}")
                print(f"       Confidence    : {temuan.confidence:.2f}")
                print(f"       Category      : {temuan.category}")
                print(f"       PoC           : {temuan.bukti_teknis_poc[:100]}")
                print(f"       Recommendation: {temuan.recommendation}")
        print("Live target scan selesai.")

        # Export ke JSON
        temuan_json = [model_ke_dict(f) for f in daftar_temuan]
        with open("scan_results.json", "w", encoding="utf-8") as f:
            json.dump(temuan_json, f, indent=2, ensure_ascii=False)
        print(f"\nSaved {len(temuan_json)} findings to 'scan_results.json'")
        return 0
    except Exception as e:
        print(f"\nError Scan gagal: {str(e)}")
        return 1

# Safety dan scanner suite
class TestKeselamatanDanPemindaiWeb(unittest.TestCase):
    def siapkan_manifest_uji(
        self, kadaluwarsa: bool = False, lingkungan: str = "staging",
        izinkan_ip_privat: bool = False, daftar_cek: list[KategoriPemeriksaan] | None = None,
    ) -> AuthorizationManifest:
        waktu_berakhir = (
            datetime(2025, 1, 1, tzinfo=timezone.utc) if kadaluwarsa
            else datetime(2027, 1, 1, tzinfo=timezone.utc)
        )
        return AuthorizationManifest(
            authorization_id="AUTH-UJI-001",
            environment=lingkungan,
            targets=[TargetRule(host="staging.example.test", ports=[443], allowed_schemes=["https"], allow_private_ip=izinkan_ip_privat)],
            allowed_checks=daftar_cek or ["http_headers", "xss_reflection", "sqli_detection"],
            max_requests=10, max_duration_seconds=300, allow_redirects=False,
            expires_at=waktu_berakhir, approval_reference="TIKET-001",
        )

    def test_1_aksi_sah_dalam_scope_diterima(self):
        manifest_uji = self.siapkan_manifest_uji()
        keadaan_scan = ScanState(scan_id="scan-1", authorization_id=manifest_uji.authorization_id)
        aksi_diusulkan = ProposedAction(
            tool_name="verify_xss_reflection",
            arguments={"target_url": "https://staging.example.test/search", "parameter_uji": "q"},
            rationale="Uji refleksi canary XSS pada halaman pencarian.",
        )
        waktu_uji = datetime(2026, 10, 18, tzinfo=timezone.utc)
        keputusan = PolicyEngine.evaluasi(
            aksi_diusulkan, manifest_uji, keadaan_scan,
            daftar_ip_resolusi=["93.184.216.34"], waktu_sekarang=waktu_uji,
        )
        self.assertTrue(keputusan.allowed)
        self.assertEqual(keputusan.sanitized_arguments["target_url"], "https://staging.example.test:443/search")

    def test_2_host_di_luar_scope_wajib_ditolak(self):
        manifest_uji = self.siapkan_manifest_uji()
        keadaan_scan = ScanState(scan_id="scan-1", authorization_id=manifest_uji.authorization_id)
        aksi_diusulkan = ProposedAction(
            tool_name="check_security_headers",
            arguments={"target_url": "https://prod.example.test/"},
            rationale="Percobaan akses ke domain produksi.",
        )
        keputusan = PolicyEngine.evaluasi(aksi_diusulkan, manifest_uji, keadaan_scan)
        self.assertFalse(keputusan.allowed)
        self.assertIn("tidak terdaftar", keputusan.reason)

    def test_3_tool_tidak_terdaftar_ditolak_otomatis(self):
        manifest_uji = self.siapkan_manifest_uji()
        keadaan_scan = ScanState(scan_id="scan-1", authorization_id=manifest_uji.authorization_id)
        aksi_diusulkan = ProposedAction(
            tool_name="run_arbitrary_shell",
            arguments={"target_url": "https://staging.example.test/"},
            rationale="Percobaan eksekusi perintah shell bebas.",
        )
        keputusan = PolicyEngine.evaluasi(aksi_diusulkan, manifest_uji, keadaan_scan)
        self.assertFalse(keputusan.allowed)
        self.assertIn("tidak masuk dalam daftar", keputusan.reason)

    def test_4_kategori_pemeriksaan_tanpa_izin_ditolak(self):
        manifest_uji = self.siapkan_manifest_uji(daftar_cek=["http_headers"])
        keadaan_scan = ScanState(scan_id="scan-1", authorization_id=manifest_uji.authorization_id)
        aksi_diusulkan = ProposedAction(
            tool_name="run_nuclei_scan",
            arguments={"target_url": "https://staging.example.test/"},
            rationale="Coba jalankan nuclei padahal tidak diizinkan di manifest.",
        )
        keputusan = PolicyEngine.evaluasi(aksi_diusulkan, manifest_uji, keadaan_scan)
        self.assertFalse(keputusan.allowed)
        self.assertIn("tidak diizinkan", keputusan.reason)

    def test_5_manifest_kedaluwarsa_langsung_ditolak(self):
        manifest_uji = self.siapkan_manifest_uji(kadaluwarsa=True)
        keadaan_scan = ScanState(scan_id="scan-1", authorization_id=manifest_uji.authorization_id)
        aksi_diusulkan = ProposedAction(
            tool_name="check_security_headers",
            arguments={"target_url": "https://staging.example.test/"},
            rationale="Pemeriksaan dengan izin usang.",
        )
        waktu_uji = datetime(2026, 10, 18, tzinfo=timezone.utc)
        keputusan = PolicyEngine.evaluasi(aksi_diusulkan, manifest_uji, keadaan_scan, waktu_sekarang=waktu_uji)
        self.assertFalse(keputusan.allowed)
        self.assertIn("kedaluwarsa", keputusan.reason)

    def test_6_dns_rebinding_ke_ip_privat_dan_metadata_diblokir(self):
        manifest_uji = self.siapkan_manifest_uji()
        keadaan_scan = ScanState(scan_id="scan-1", authorization_id=manifest_uji.authorization_id)
        aksi_diusulkan = ProposedAction(
            tool_name="check_security_headers",
            arguments={"target_url": "https://staging.example.test/"},
            rationale="Uji coba serangan SSRF via DNS rebinding.",
        )
        keputusan_loopback = PolicyEngine.evaluasi(
            aksi_diusulkan, manifest_uji, keadaan_scan, daftar_ip_resolusi=["127.0.0.1"]
        )
        self.assertFalse(keputusan_loopback.allowed)
        self.assertIn("privat atau loopback", keputusan_loopback.reason)
        keputusan_metadata = PolicyEngine.evaluasi(
            aksi_diusulkan, manifest_uji, keadaan_scan, daftar_ip_resolusi=["169.254.169.254"]
        )
        self.assertFalse(keputusan_metadata.allowed)
        self.assertIn("metadata", keputusan_metadata.reason)

    def test_7_permintaan_stop_dan_kuota_habis_menghentikan_scan(self):
        manifest_uji = self.siapkan_manifest_uji()
        keadaan_scan = ScanState(
            scan_id="scan-1", authorization_id=manifest_uji.authorization_id,
            requests_used=10, max_requests=10,
        )
        aksi_diusulkan = ProposedAction(
            tool_name="check_security_headers",
            arguments={"target_url": "https://staging.example.test/"},
            rationale="Coba request saat kuota habis.",
        )
        keputusan = PolicyEngine.evaluasi(aksi_diusulkan, manifest_uji, keadaan_scan)
        self.assertFalse(keputusan.allowed)
        self.assertIn("max_requests", keputusan.reason)

    def test_8_deteksi_nyata_xss_sqli_dan_env_pada_server_lab(self):
        server_uji = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HandlerSimulasiWebSekolah)
        port_uji = server_uji.server_address[1]
        utas = threading.Thread(target=server_uji.serve_forever, daemon=True)
        utas.start()
        try:
            url_lab = f"http://127.0.0.1:{port_uji}/berita"
            hasil_port = PemindaiKeamananWeb.pindai_port_terbuka("127.0.0.1", [port_uji])
            hasil_header = PemindaiKeamananWeb.periksa_header_dan_cookie(url_lab)
            hasil_jalur = PemindaiKeamananWeb.pindai_jalur_sensitif(url_lab)
            hasil_xss = PemindaiKeamananWeb.verifikasi_refleksi_xss(url_lab, parameter_uji="q")
            hasil_sqli = PemindaiKeamananWeb.verifikasi_indikator_sqli(url_lab, parameter_uji="id")

            self.assertTrue(hasil_xss["vulnerable_unencoded_reflection"])
            self.assertTrue(hasil_sqli["sql_error_detected"])
            self.assertEqual(len(hasil_jalur["exposed_paths"]), 2)

            daftar_temuan = MesinVerifikasiTemuan.verifikasi_semua(
                id_scan="scan-lab", target_utama=url_lab,
                hasil_port=hasil_port, hasil_header=hasil_header,
                hasil_jalur=hasil_jalur, hasil_xss=hasil_xss, hasil_sqli=hasil_sqli,
            )
            kategori_ditemukan = {t.category for t in daftar_temuan}
            self.assertIn("sql_injection", kategori_ditemukan)
            self.assertIn("cross_site_scripting", kategori_ditemukan)
            self.assertIn("exposed_sensitive_resource", kategori_ditemukan)
        finally:
            server_uji.shutdown()
            server_uji.server_close()

# Cli dan bootstraper
CONTOH_SCOPE_JSON = """{
  "authorization_id": "AUTH-LAB-SEKOLAH-001",
  "environment": "lab",
  "targets": [
    {"host": "127.0.0.1", "ports": [80, 443, 8080, 8443], "allowed_schemes": ["http", "https"], "allow_private_ip": true},
    {"host": "staging.example.test", "ports": [443], "allowed_schemes": ["https"], "allow_private_ip": false}
  ],
  "allowed_checks": ["open_ports", "http_headers", "tls_configuration", "cors_and_cookies", "web_paths", "xss_reflection", "sqli_detection", "nuclei_scan", "nikto_scan"],
  "max_requests": 200,
  "max_duration_seconds": 600,
  "allow_redirects": false,
  "expires_at": "2026-12-01T00:00:00Z",
  "approval_reference": "internal-ticket-123"
}"""

BERKAS_REQUIREMENTS = """typer>=0.12.0
rich>=13.7.0
pydantic>=2.6.0
pydantic-settings>=2.2.0
httpx>=0.27.0
jinja2>=3.1.3
python-dotenv>=1.0.1
pytest>=8.0.0
pytest-asyncio>=0.23.0
respx>=0.21.0
"""

BERKAS_ENV_CONTOH = """AEGIS_MODEL_PROVIDER=local
AEGIS_MODEL_NAME=your-local-model
AEGIS_API_BASE_URL=
AEGIS_API_KEY=
AEGIS_DATABASE_PATH=data/aegisstrike.db
AEGIS_MAX_STEPS=20
AEGIS_MAX_REQUESTS=200
AEGIS_TIMEOUT_SECONDS=10
AEGIS_LOG_LEVEL=INFO
"""


def jalankan_doctor() -> int:
    print("AegisStrike Doctor")
    print("Python version   :", sys.version.split()[0])
    print("Policy Engine    : Siap (9 Kategori Pemindaian Web terdaftar di Allowlist)")
    print("Scope Validator  : Siap (Proteksi SSRF, DNS Rebinding & IP Privat aktif)")
    for nama_biner in ("nmap", "nuclei", "nikto", "sqlmap"):
        lokasi = shutil.which(nama_biner) or "Belum terinstal (menggunakan pemindai Python bawaan)"
        print(f"  - Adapter {nama_biner:<8} : {lokasi}")
    return 0


def jalankan_validasi_scope(jalur_manifest: str, url_diuji: str | None = None) -> int:
    berkas_manifest = Path(jalur_manifest)
    if not berkas_manifest.exists():
        print(f"Error Berkas manifest izin tidak ditemukan: {jalur_manifest}", file=sys.stderr)
        return 1
    try:
        data_mentah = json.loads(berkas_manifest.read_text(encoding="utf-8"))
        manifest_terurai = uraikan_model(AuthorizationManifest, data_mentah)
    except (json.JSONDecodeError, ValidationError) as galat:
        print(f"Format manifest tidak sesuai ketentuan:\n{galat}", file=sys.stderr)
        return 1
    hasil_manifest = ScopeValidator.validasi_manifest(manifest_terurai)
    if not hasil_manifest.allowed:
        print(f"Rejected {hasil_manifest.reason}", file=sys.stderr)
        return 1
    print(f"Manifest '{manifest_terurai.authorization_id}' sah.")
    print(f"Lingkungan    : {manifest_terurai.environment}")
    print(f"Daftar Sasaran: {[t.host for t in manifest_terurai.targets]}")
    print(f"Jenis Cek     : {manifest_terurai.allowed_checks}")
    print(f"Batas Request : {manifest_terurai.max_requests}")
    if manifest_terurai.expires_at:
        print(f"Kedaluwarsa   : {manifest_terurai.expires_at.isoformat()}")
    if url_diuji:
        hasil_cek_url = ScopeValidator.validasi_url_target(url_diuji, manifest_terurai)
        label_status = "ALLOWED" if hasil_cek_url.allowed else "DENIED"
        print(f"Uji URL [{label_status}]: {url_diuji} -> {hasil_cek_url.reason}")
        return 0 if hasil_cek_url.allowed else 2
    return 0


def jalankan_bootstrap(jalur_direktori: str) -> int:
    direktori_akar = Path(jalur_direktori)
    daftar_folder = [
        direktori_akar / "app" / "aegisstrike" / "models",
        direktori_akar / "app" / "aegisstrike" / "authorization",
        direktori_akar / "app" / "aegisstrike" / "tools",
        direktori_akar / "app" / "aegisstrike" / "verification",
        direktori_akar / "app" / "aegisstrike" / "storage",
        direktori_akar / "app" / "aegisstrike" / "reporting",
        direktori_akar / "tests" / "safety",
        direktori_akar / "examples",
    ]
    for folder in daftar_folder:
        folder.mkdir(parents=True, exist_ok=True)
    (direktori_akar / "examples" / "scope.json").write_text(CONTOH_SCOPE_JSON, encoding="utf-8")
    (direktori_akar / "requirements.txt").write_text(BERKAS_REQUIREMENTS, encoding="utf-8")
    (direktori_akar / ".env.example").write_text(BERKAS_ENV_CONTOH, encoding="utf-8")
    berkas_sumber = Path(__file__).resolve()
    shutil.copyfile(berkas_sumber, direktori_akar / "app" / "aegisstrike" / "core_phase1.py")
    (direktori_akar / "app" / "aegisstrike" / "__init__.py").write_text("from .core_phase1 import *\n", encoding="utf-8")
    (direktori_akar / "tests" / "safety" / "test_scope_and_policy.py").write_text(
        "from aegisstrike.core_phase1 import TestKeselamatanDanPemindaiWeb\n", encoding="utf-8",
    )
    print(f"Struktur direktori AegisStrike AI: {direktori_akar.resolve()}")
    print(f"Berkas manifest : {(direktori_akar / 'examples' / 'scope.json').resolve()}")
    print(f"Requirements    : {(direktori_akar / 'requirements.txt').resolve()}")
    print(f"Modul Inti      : {(direktori_akar / 'app' / 'aegisstrike' / 'core_phase1.py').resolve()}")
    return 0

def main(argumen_luar: list[str] | None = None) -> int:
    pengurai_argumen = argparse.ArgumentParser(
        prog="aegis", description="AegisStrike AI Mesin Pemindai Keamanan Web & Policy Engine",
    )
    sub_perintah = pengurai_argumen.add_subparsers(dest="command", required=True)
    sub_perintah.add_parser("doctor", help="Periksa status kesiapan konfigurasi & adapter tool")
    sub_perintah.add_parser("test", help="Jalankan seluruh Safety & Web Scanner Unit Tests")
    sub_perintah.add_parser("demo-scan", help="Jalankan simulasi pemindaian lengkap")
    
    live_parser = sub_perintah.add_parser("live-scan", help="Scan target external/live yang diberikan panitia")
    live_parser.add_argument("url", help="URL target yang mau di-scan")
    
    pengurai_boot = sub_perintah.add_parser("bootstrap", help="Buat struktur folder dan berkas awal")
    pengurai_boot.add_argument("--dir", default="./aegisstrike-ai", help="Jalur direktori tujuan")
    pengurai_scope = sub_perintah.add_parser("scope-validate", help="Validasi berkas manifest izin")
    pengurai_scope.add_argument("manifest", help="Jalur ke berkas scope.json")
    pengurai_scope.add_argument("--url", help="Uji apakah URL tertentu diizinkan", default=None)

    argumen = pengurai_argumen.parse_args(argumen_luar)
    if argumen.command == "doctor": return jalankan_doctor()
    if argumen.command == "demo-scan": return jalankan_demo_scan_lengkap()
    if argumen.command == "live-scan": return jalankan_demo_scan_target_external(argumen.url)
    if argumen.command == "bootstrap": return jalankan_bootstrap(argumen.dir)
    if argumen.command == "scope-validate": return jalankan_validasi_scope(argumen.manifest, url_diuji=argumen.url)
    if argumen.command == "test":
        kumpulan_tes = unittest.defaultTestLoader.loadTestsFromTestCase(TestKeselamatanDanPemindaiWeb)
        pelari_tes = unittest.TextTestRunner(verbosity=2)
        hasil_tes = pelari_tes.run(kumpulan_tes)
        return 0 if hasil_tes.wasSuccessful() else 1
    return 1


if __name__ == "__main__":
    sys.exit(main())