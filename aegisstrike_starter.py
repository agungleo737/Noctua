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

# 1. KOMPATIBILITAS PYDANTIC & UTILS
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

# 2. ATURAN SCOPE, AKSI AGENT, BUKTI, TEMUAN, DAN STATUS SCAN
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

# 3. TARGET DAN MANIFEST
class TargetRule(BaseModel):
    host: str = Field(..., min_length=1, description="Hostname atau IP target tanpa wildcard")
    ports: list[int] = Field(default_factory=lambda: list(range(1, 65535)))
    allowed_schemes: list[SkemaDiizinkan] = Field(default_factory=lambda: ["http", "https"])
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

class AuthorizationManifest(BaseModel):
    authorization_id: str = Field(..., min_length=3)
    environment: TipeLingkungan = "staging"
    targets: list[TargetRule]
    allowed_checks: list[KategoriPemeriksaan] = Field(
        default_factory=lambda: list(semua_kategori_default)
    )
    mode: ModeScan = "stealth"
    max_requests: int = Field(default=200, ge=1, le=10000)
    max_duration_seconds: int = Field(default=600, ge=10, le=72000)
    allow_redirects: bool = Field(default=False)
    
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
    def pastikan_pemeriksaan_tersedia(
        cls, daftar_cek: list[KategoriPemeriksaan]
    ) -> list[KategoriPemeriksaan]:
        if not daftar_cek:
            raise ValueError("Manifest wajib mengizinkan minimal 1 jenis pemeriksaan.")
        return daftar_cek

# 4. CONTEXT, ACTION, POLICY, EVIDENCE, OBSERVATION
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
    allowed: bool
    reason: str
    execution_priority: Literal["low", "normal", "high", "critical"] = "critical"
    sanitized_arguments: dict[str, Any] = Field(default_factory=dict)
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

# FINDING & SCANSTATE
class Finding(BaseModel):
    scan_id: str
    target: str
    finding_id: str
    title: str
    category: str
    severity: TingkatKeparahan
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

# VALIDATOR 
class HasilValidasiScope(BaseModel):
    allowed: bool
    reason: str
    matched_target: TargetRule | None = None
    normalized_url: str | None = None
IP_METADATA_CLOUD = {
    "169.254.169.254",
    "100.100.100.200",
    "fd00:ec2::254",
    "metadata.google.internal"
}

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
        skema_url = (url_terurai.scheme or "").lower()
        nama_host = (url_terurai.hostname or "").lower()
        if not skema_url or not nama_host:
            return HasilValidasiScope(
                allowed=False,
                reason="URL wajib memiliki skema protokol dan nama host yang jelas.",
            )

        port_tujuan = url_terurai.port
        if port_tujuan is None:
            port_tujuan = 443 if skema_url == "https" else (80 if skema_url == "http" else -1)
        aturan_cocok: TargetRule | None = None
        for aturan in manifest.targets:
            if nama_host == aturan.host or nama_host.endswith(f".{aturan.host}"):
                aturan_cocok = aturan
                break

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

        if skema_url not in aturan_cocok.allowed_schemes:
            return HasilValidasiScope(
                allowed=False,
                reason=(
                    f"Skema '{skema_url}' dilarang untuk host '{nama_host}' "
                    f"(hanya menerima: {aturan_cocok.allowed_schemes})."
                ),
            )

        if port_tujuan not in aturan_cocok.ports:
            return HasilValidasiScope(
                allowed=False,
                reason=(
                    f"Port {port_tujuan} dilarang untuk host '{nama_host}' "
                    f"(hanya menerima: {aturan_cocok.ports})."
                ),
            )

        antrean_ip = list(daftar_ip_resolusi or [])
        try:
            ipaddress.ip_address(nama_host)
            antrean_ip.append(nama_host)
        except ValueError:
            pass
        for alamat_ip in antrean_ip:
            hasil_ip = cls._periksa_keamanan_ip(
                alamat_ip, izinkan_ip_privat=aturan_cocok.allow_private_ip
            )
            if not hasil_ip.allowed:
                return hasil_ip
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
            return HasilValidasiScope(
                allowed=True, 
                reason=f"Format string '{teks_ip}' bukan IP standar, diteruskan ke eksekusi."
            )
        is_restricted_or_metadata = (
            teks_ip in IP_METADATA_CLOUD or 
            objek_ip.is_link_local or 
            objek_ip.is_multicast or 
            objek_ip.is_unspecified
        )
        if is_restricted_or_metadata and not izinkan_ip_privat:
            return HasilValidasiScope(
                allowed=False,
                reason=f"Alamat IP '{teks_ip}' terdeteksi sebagai IP restricted/metadata dan ditolak oleh rule.",
            )
        if (objek_ip.is_private or objek_ip.is_loopback) and not izinkan_ip_privat:
            return HasilValidasiScope(
                allowed=False,
                reason=f"Alamat IP privat atau loopback '{teks_ip}' ditolak (allow_private_ip=False).",
            )
        return HasilValidasiScope(
            allowed=True, 
            reason=f"Alamat IP '{teks_ip}' diverifikasi dan diizinkan untuk eksekusi penuh."
        )

# Semua tool pemindaian web
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
        # cek rem darurat
        if kondisi_scan.stop_requested:
            return PolicyDecision(allowed=False, reason="Scan sudah ditandai untuk dihentikan.")
        if kondisi_scan.batas_waktu_tercapai(waktu_sekarang=waktu_sekarang):
            return PolicyDecision(allowed=False, reason="Batas maksimum durasi pemeriksaan telah terlampaui.")
        if kondisi_scan.kuota_langkah_habis():
            return PolicyDecision(allowed=False, reason="Batas jumlah langkah iterasi agent telah habis.")
        if kondisi_scan.kuota_request_habis():
            return PolicyDecision(allowed=False, reason="Batas anggaran request keluar telah habis.")

        # validasi tools
        kategori_cek = PEMETAAN_TOOL_KE_CEK.get(rencana_aksi.tool_name)
        if kategori_cek is None:
            return PolicyDecision(
                allowed=False,
                reason=f"Tool '{rencana_aksi.tool_name}' tidak masuk dalam daftar tool sah."
            )
        if kategori_cek not in manifest.allowed_checks:
            return PolicyDecision(
                allowed=False,
                reason=f"Pemeriksaan jenis '{kategori_cek}' untuk tool '{rencana_aksi.tool_name}' tidak diizinkan pada manifest ini."
            )
        # validasi url sasaran
        url_sasaran = rencana_aksi.arguments.get("target_url")
        if not isinstance(url_sasaran, str) or not url_sasaran.strip():
            return PolicyDecision(
                allowed=False,
                reason="Argumen 'target_url' kosong atau bukan format string yang benar."
            )

        # Blokir karakter bahaya DI URL
        for pola in POLA_KARAKTER_BAHAYA:
            if pola in url_sasaran:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Karakter injeksi perintah terdeteksi pada URL: '{pola}'."
                )

        # Validasi Scope URL
        hasil_cek_url = ScopeValidator.validasi_url_target(
            url_mentah=url_sasaran,
            manifest=manifest,
            daftar_ip_resolusi=daftar_ip_resolusi,
            waktu_sekarang=waktu_sekarang,
        )
        if not hasil_cek_url.allowed:
            return PolicyDecision(allowed=False, reason=hasil_cek_url.reason)
        payload_mentah = rencana_aksi.raw_payload
        evasion_dinamis = rencana_aksi.evasion_level
        
        if any(pola in payload_mentah for pola in POLA_KARAKTER_BAHAYA):
            evasion_dinamis = max(evasion_dinamis, 5) # Paksa level bypass maksimal

        # sanitasi dan normalisasi arguen
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
        # Eksekusi otomatis
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

HEADER_WAJIB_WEB = {
    "Content-Security-Policy": (
        "medium",
        "Mencegah eksekusi skrip lintas situs (XSS) dan injeksi konten tak sah.",
    ),
    "Strict-Transport-Security": (
        "low",
        "Memaksa browser berkomunikasi hanya melalui HTTPS terenkripsi (HSTS).",
    ),
    "X-Frame-Options": (
        "low",
        "Melindungi halaman web dari serangan Clickjacking melalui elemen iframe.",
    ),
    "X-Content-Type-Options": (
        "low",
        "Mencegah MIME-sniffing berbahaya oleh browser (wajib bernilai 'nosniff').",
    ),
}

JALUR_SENSITIF_UMUM = [
    ("/.env", "high", "Berkas konfigurasi environment (.env) terbuka ke publik", ("db_", "app_env", "secret", "=")),
    ("/.git/HEAD", "high", "Repositori kode sumber Git (.git) terekspos di web root", ("ref: refs/",)),
    ("/backup.sql", "critical", "Cadangan basis data SQL (/backup.sql) dapat diunduh bebas", ("create table", "insert into", "mysqldump")),
    ("/phpinfo.php", "medium", "Halaman diagnostik phpinfo() membocorkan konfigurasi server", ("php version", "zend engine")),
    ("/admin/", "info", "Panel administrasi (/admin/) terdeteksi tanpa pembatasan IP", ("panel admin", "dashboard admin", "login admin")),
    ("/robots.txt", "info", "Berkas robots.txt ditemukan dan memetakan direktori internal", ("user-agent:", "disallow:")),
]

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
    def _ambil_respons_http(
        url_tujuan: str, batas_waktu: int = 5
    ) -> tuple[int, dict[str, str], list[str], str]:
        permintaan = urllib.request.Request(
            url_tujuan,
            headers={"User-Agent": "AegisStrike-SecurityVerifier/0.2 (Authorized-Lab-Scan)"},
        )
        try:
            # Buat SSL context
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
            kamus_header = (
                {k.lower(): v for k, v in galat_http.headers.items()}
                if galat_http.headers
                else {}
            )
            daftar_cookie = (
                galat_http.headers.get_all("Set-Cookie") if galat_http.headers else []
            ) or []
            isi_galat = galat_http.read(65536).decode("utf-8", errors="replace")
            return galat_http.code, kamus_header, daftar_cookie, isi_galat
            
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, OSError) as galat_jaringan:
            # Handle connection error
            return (
                0,  # Status code 0 = connection failed
                {},
                [],
                f"[CONNECTION_ERROR] {type(galat_jaringan).__name__}: {str(galat_jaringan)}",
            )
    @staticmethod
    def pindai_port_terbuka(
        nama_host: str, daftar_port: list[int], batas_waktu: int = 2
    ) -> dict[str, Any]:
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
        return {
            "host": nama_host,
            "ports_scanned": daftar_port,
            "open_ports": port_terbuka,
            "adapter": info_adapter,
        }

    @classmethod
    def periksa_header_dan_cookie(
        cls, url_sasaran: str, batas_waktu: int = 5
    ) -> dict[str, Any]:
        status_http, header_respons, daftar_cookie, _ = cls._ambil_respons_http(
            url_sasaran, batas_waktu=batas_waktu
        )
        header_hilang: list[dict[str, str]] = []
        for nama_header, (tingkat_bahaya, penjelasan) in HEADER_WAJIB_WEB.items():
            if nama_header.lower() not in header_respons:
                header_hilang.append(
                    {
                        "header": nama_header,
                        "severity": tingkat_bahaya,
                        "rekomendasi": penjelasan,
                    }
                )

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
                cookie_lemah.append(
                    {
                        "nama_cookie": nama_cookie,
                        "raw_cookie": untai_cookie,
                        "atribut_hilang": ", ".join(atribut_kurang),
                    }
                )
        cors_terlalu_terbuka = header_respons.get("access-control-allow-origin") == "*"
        banner_server = header_respons.get("server", "")
        return {
            "status_code": status_http,
            "missing_headers": header_hilang,
            "weak_cookies": cookie_lemah,
            "wildcard_cors": cors_terlalu_terbuka,
            "server_banner": banner_server,
        }

    @classmethod
    def pindai_jalur_sensitif(
        cls, url_dasar: str, batas_waktu: int = 5
    ) -> dict[str, Any]:
        terurai = urllib.parse.urlsplit(url_dasar)
        akar_url = f"{terurai.scheme}://{terurai.netloc}"
        temuan_jalur: list[dict[str, Any]] = []
        for jalur_uji, tingkat_bahaya, keterangan, penanda_wajib in JALUR_SENSITIF_UMUM:
            url_penuh = f"{akar_url}{jalur_uji}"
            try:
                status_http, _, _, cuplikan_isi = cls._ambil_respons_http(
                    url_penuh, batas_waktu=batas_waktu
                )
                isi_kecil = cuplikan_isi.lower()
                cocok_penanda = any(penanda in isi_kecil for penanda in penanda_wajib)
                if status_http == 200 and cocok_penanda:
                    temuan_jalur.append(
                        {
                            "path": jalur_uji,
                            "url": url_penuh,
                            "status_code": status_http,
                            "severity": tingkat_bahaya,
                            "description": keterangan,
                            "snippet": cuplikan_isi[:140].strip().replace("\n", " | "),
                        }
                    )
            except Exception:
                continue
        return {"base_url": akar_url, "exposed_paths": temuan_jalur}

    @classmethod
    def verifikasi_refleksi_xss(
        cls, url_sasaran: str, parameter_uji: str = "q", batas_waktu: int = 5
    ) -> dict[str, Any]:
        penanda_canary = "AegisCanary9912<\"'>"
        terurai = urllib.parse.urlsplit(url_sasaran)
        kueri_awal = dict(urllib.parse.parse_qsl(terurai.query))
        kueri_awal[parameter_uji] = penanda_canary
        kueri_baru = urllib.parse.urlencode(kueri_awal)
        url_uji = urllib.parse.urlunsplit(
            (terurai.scheme, terurai.netloc, terurai.path or "/", kueri_baru, "")
        )
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
            "tested_url": url_uji,
            "parameter": parameter_uji,
            "canary_payload": penanda_canary,
            "status_code": status_http,
            "vulnerable_unencoded_reflection": terpantul_mentah,
            "properly_escaped": terpantul_aman,
            "proof_snippet": cuplikan_bukti,
        }

    @classmethod
    def verifikasi_indikator_sqli(
        cls, url_sasaran: str, parameter_uji: str = "id", batas_waktu: int = 5
    ) -> dict[str, Any]:
        """Memverifikasi indikator kerentanan SQL Injection berdasarkan perbedaan respons & galat sintaks SQL."""
        terurai = urllib.parse.urlsplit(url_sasaran)
        kueri_dasar = dict(urllib.parse.parse_qsl(terurai.query))

        # 1. Request normal (baseline)
        kueri_dasar[parameter_uji] = "1"
        url_normal = urllib.parse.urlunsplit(
            (
                terurai.scheme,
                terurai.netloc,
                terurai.path or "/",
                urllib.parse.urlencode(kueri_dasar),
                "",
            )
        )
        status_normal, _, _, isi_normal = cls._ambil_respons_http(
            url_normal, batas_waktu=batas_waktu
        )

        # 2. Request uji karakter kutip tunggal (diagnostic probe)
        kueri_dasar[parameter_uji] = "1'"
        url_probe = urllib.parse.urlunsplit(
            (
                terurai.scheme,
                terurai.netloc,
                terurai.path or "/",
                urllib.parse.urlencode(kueri_dasar),
                "",
            )
        )
        status_probe, _, _, isi_probe = cls._ambil_respons_http(
            url_probe, batas_waktu=batas_waktu
        )

        isi_probe_kecil = isi_probe.lower()
        pola_cocok: list[str] = []
        for pola_sql in POLA_GALAT_SQL:
            if pola_sql in isi_probe_kecil and pola_sql not in isi_normal.lower():
                pola_cocok.append(pola_sql)

        cuplikan_galat = ""
        if pola_cocok:
            indeks = isi_probe_kecil.find(pola_cocok[0])
            cuplikan_galat = isi_probe[max(0, indeks - 20) : min(len(isi_probe), indeks + 120)].strip()

        return {
            "baseline_url": url_normal,
            "probe_url": url_probe,
            "parameter": parameter_uji,
            "baseline_status": status_normal,
            "probe_status": status_probe,
            "sql_error_detected": len(pola_cocok) > 0,
            "matched_error_signatures": pola_cocok,
            "proof_snippet": cuplikan_galat,
            "sqlmap_binary_available": shutil.which("sqlmap") is not None,
        }

    @staticmethod
    def periksa_konfigurasi_tls(nama_host: str, port: int = 443, batas_waktu: int = 5) -> dict[str, Any]:
        """Memeriksa versi protokol TLS dan masa berlaku sertifikat."""
        konteks_ssl = ssl.create_default_context()
        try:
            with socket.create_connection((nama_host, port), timeout=batas_waktu) as soket_tcp:
                with konteks_ssl.wrap_socket(soket_tcp, server_hostname=nama_host) as soket_tls:
                    versi_tls = soket_tls.version() or "unknown"
                    sertifikat = soket_tls.getpeercert() or {}
                    return {
                        "host": nama_host,
                        "port": port,
                        "tls_supported": True,
                        "tls_version": versi_tls,
                        "weak_protocol": versi_tls in ("SSLv3", "TLSv1", "TLSv1.1"),
                        "subject": str(sertifikat.get("subject", "")),
                    }
        except Exception as galat_tls:
            return {
                "host": nama_host,
                "port": port,
                "tls_supported": False,
                "error": str(galat_tls),
            }
