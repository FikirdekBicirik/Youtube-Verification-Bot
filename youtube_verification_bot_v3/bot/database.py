# bot/database.py
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from threading import Lock
import uuid
import hashlib

from utils.logger import Logger

class Database:
    """Gelişmiş veritabanı sistemi"""
    
    def __init__(self):
        self.logger = Logger()
        self.data_dir = "data"
        self.lock = Lock()
        
        # Dosya yolları
        self.verified_users_file = os.path.join(self.data_dir, "verified_users.json")
        self.pending_verifications_file = os.path.join(self.data_dir, "pending_verifications.json")
        self.user_attempts_file = os.path.join(self.data_dir, "user_attempts.json")
        self.statistics_file = os.path.join(self.data_dir, "statistics.json")
        self.security_events_file = os.path.join(self.data_dir, "security_events.json")
        self.admin_actions_file = os.path.join(self.data_dir, "admin_actions.json")
        
        self.ensure_files_exist()
        self.load_initial_data()
    
    def ensure_files_exist(self):
        """Gerekli dosya ve klasörleri oluştur"""
        os.makedirs(self.data_dir, exist_ok=True)
        
        default_files = {
            self.verified_users_file: {},
            self.pending_verifications_file: {},
            self.user_attempts_file: {},
            self.statistics_file: {
                "total_verified": 0,
                "total_rejected": 0,
                "total_attempts": 0,
                "spam_blocked": 0,
                "duplicates_blocked": 0,
                "created_at": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat()
            },
            self.security_events_file: [],
            self.admin_actions_file: []
        }
        
        for file_path, default_data in default_files.items():
            if not os.path.exists(file_path):
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(default_data, f, indent=2, ensure_ascii=False)
                    self.logger.info(f"Veritabanı dosyası oluşturuldu: {file_path}")
                except Exception as e:
                    self.logger.error(f"Dosya oluşturma hatası {file_path}: {str(e)}")
    
    def load_initial_data(self):
        """Başlangıç verilerini yükle"""
        try:
            # Eski formatları yeni formata güncelle
            self.migrate_old_format()
            self.logger.info("Veritabanı başlatıldı")
        except Exception as e:
            self.logger.error(f"Veritabanı başlatma hatası: {str(e)}")
    
    def migrate_old_format(self):
        """Eski veri formatlarını yeni formata geçir"""
        try:
            # Verified users migration
            verified_data = self.load_json(self.verified_users_file)
            updated = False
            
            for user_id, user_data in verified_data.items():
                if isinstance(user_data, str):  # Eski format: sadece username
                    verified_data[user_id] = {
                        "username": user_data,
                        "verified_at": datetime.now().isoformat(),
                        "verification_count": 1,
                        "manual_verification": False,
                        "admin_id": None,
                        "confidence_score": 100,
                        "channel_name": None
                    }
                    updated = True
                elif isinstance(user_data, dict):
                    # Eksik alanları ekle
                    if "id" not in user_data:
                        user_data["id"] = str(uuid.uuid4())
                        updated = True
                    if "verification_count" not in user_data:
                        user_data["verification_count"] = 1
                        updated = True
                    if "security_score" not in user_data:
                        user_data["security_score"] = 100
                        updated = True
            
            if updated:
                self.save_json(self.verified_users_file, verified_data)
                self.logger.info("Doğrulanmış kullanıcılar veri formatı güncellendi")
                
        except Exception as e:
            self.logger.error(f"Veri migration hatası: {str(e)}")
    
    def load_json(self, file_path: str, default: Any = None) -> Any:
        """JSON dosyası yükle"""
        try:
            if not os.path.exists(file_path):
                return default or {}
            
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.warning(f"JSON yükleme hatası {file_path}: {str(e)}")
            return default or {}
        except Exception as e:
            self.logger.error(f"Beklenmeyen JSON hatası {file_path}: {str(e)}")
            return default or {}
    
    def save_json(self, file_path: str, data: Any):
        """JSON dosyası kaydet"""
        try:
            # Backup oluştur
            if os.path.exists(file_path):
                backup_path = f"{file_path}.backup"
                with open(file_path, 'r', encoding='utf-8') as src:
                    with open(backup_path, 'w', encoding='utf-8') as dst:
                        dst.write(src.read())
            
            # Ana dosyayı kaydet
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            self.logger.error(f"JSON kaydetme hatası {file_path}: {str(e)}")
            # Backup'tan geri yükle
            backup_path = f"{file_path}.backup"
            if os.path.exists(backup_path):
                try:
                    with open(backup_path, 'r', encoding='utf-8') as src:
                        with open(file_path, 'w', encoding='utf-8') as dst:
                            dst.write(src.read())
                    self.logger.info(f"Backup'tan geri yüklendi: {file_path}")
                except:
                    pass
    
    # Doğrulanmış kullanıcı işlemleri
    def add_verified_user(self, user_id: int, username: str, manual: bool = False, 
                         admin_id: int = None, confidence: int = 100, 
                         channel_name: str = None) -> bool:
        """Doğrulanmış kullanıcı ekle"""
        try:
            with self.lock:
                data = self.load_json(self.verified_users_file)
                
                verification_data = {
                    "id": str(uuid.uuid4()),
                    "username": username,
                    "verified_at": datetime.now().isoformat(),
                    "verification_count": data.get(str(user_id), {}).get("verification_count", 0) + 1,
                    "manual_verification": manual,
                    "admin_id": admin_id,
                    "confidence_score": confidence,
                    "channel_name": channel_name,
                    "last_updated": datetime.now().isoformat(),
                    "security_score": 100,
                    "notes": []
                }
                
                data[str(user_id)] = verification_data
                self.save_json(self.verified_users_file, data)
                
                # İstatistikleri güncelle
                self.update_statistics("total_verified", 1)
                
                self.logger.success(f"Kullanıcı doğrulandı: {username} ({user_id})", user_id=user_id)
                return True
                
        except Exception as e:
            self.logger.error(f"Kullanıcı ekleme hatası: {str(e)}", user_id=user_id)
            return False
    
    def remove_verified_user(self, user_id: int) -> bool:
        """Doğrulanmış kullanıcıyı kaldır"""
        try:
            with self.lock:
                data = self.load_json(self.verified_users_file)
                
                if str(user_id) in data:
                    removed_user = data.pop(str(user_id))
                    self.save_json(self.verified_users_file, data)
                    
                    # İstatistikleri güncelle
                    self.update_statistics("total_verified", -1)
                    
                    self.logger.info(f"Doğrulanmış kullanıcı kaldırıldı: {removed_user.get('username', 'Unknown')} ({user_id})", user_id=user_id)
                    return True
                else:
                    self.logger.warning(f"Kaldırılacak kullanıcı bulunamadı: {user_id}", user_id=user_id)
                    return False
                    
        except Exception as e:
            self.logger.error(f"Kullanıcı kaldırma hatası: {str(e)}", user_id=user_id)
            return False
    
    def is_user_verified(self, user_id: int) -> bool:
        """Kullanıcı doğrulanmış mı kontrol et"""
        try:
            data = self.load_json(self.verified_users_file)
            return str(user_id) in data
        except Exception as e:
            self.logger.error(f"Doğrulama kontrolü hatası: {str(e)}", user_id=user_id)
            return False
    
    def get_verified_user_data(self, user_id: int) -> Optional[Dict]:
        """Doğrulanmış kullanıcı verilerini getir"""
        try:
            data = self.load_json(self.verified_users_file)
            return data.get(str(user_id))
        except Exception as e:
            self.logger.error(f"Kullanıcı veri alma hatası: {str(e)}", user_id=user_id)
            return None
    
    def get_all_verified_users(self) -> Dict:
        """Tüm doğrulanmış kullanıcıları getir"""
        try:
            return self.load_json(self.verified_users_file)
        except Exception as e:
            self.logger.error(f"Tüm kullanıcıları alma hatası: {str(e)}")
            return {}
    
    def update_user_security_score(self, user_id: int, score_change: int, reason: str):
        """Kullanıcı güvenlik skorunu güncelle"""
        try:
            with self.lock:
                data = self.load_json(self.verified_users_file)
                
                if str(user_id) in data:
                    current_score = data[str(user_id)].get("security_score", 100)
                    new_score = max(0, min(100, current_score + score_change))
                    
                    data[str(user_id)]["security_score"] = new_score
                    data[str(user_id)]["last_updated"] = datetime.now().isoformat()
                    
                    if "notes" not in data[str(user_id)]:
                        data[str(user_id)]["notes"] = []
                    
                    data[str(user_id)]["notes"].append({
                        "timestamp": datetime.now().isoformat(),
                        "type": "security_score_change",
                        "old_score": current_score,
                        "new_score": new_score,
                        "change": score_change,
                        "reason": reason
                    })
                    
                    self.save_json(self.verified_users_file, data)
                    
                    self.logger.info(f"Güvenlik skoru güncellendi: {user_id} - {current_score} -> {new_score} ({reason})", user_id=user_id)
                    
        except Exception as e:
            self.logger.error(f"Güvenlik skoru güncelleme hatası: {str(e)}", user_id=user_id)
    
    # Bekleyen doğrulama işlemleri
    def add_pending_verification(self, user_id: int, message_id: int, image_url: str, username: str):
        """Bekleyen doğrulama ekle"""
        try:
            with self.lock:
                data = self.load_json(self.pending_verifications_file)
                
                verification_data = {
                    "user_id": user_id,
                    "username": username,
                    "image_url": image_url,
                    "submitted_at": datetime.now().isoformat(),
                    "status": "pending",
                    "attempts": self.get_user_attempt_count(user_id) + 1,
                    "ip_hash": None,  # Discord'dan IP alamıyoruz
                    "user_agent_hash": None
                }
                
                data[str(message_id)] = verification_data
                self.save_json(self.pending_verifications_file, data)
                
                # Kullanıcı deneme sayısını artır
                self.increment_user_attempts(user_id, username)
                
                self.logger.info(f"Bekleyen doğrulama eklendi: {username} ({user_id})", user_id=user_id)
                
        except Exception as e:
            self.logger.error(f"Bekleyen doğrulama ekleme hatası: {str(e)}", user_id=user_id)
    
    def update_verification_status(self, message_id: int, status: str, admin_id: int = None):
        """Doğrulama durumunu güncelle"""
        try:
            with self.lock:
                data = self.load_json(self.pending_verifications_file)
                
                if str(message_id) in data:
                    data[str(message_id)]["status"] = status
                    data[str(message_id)]["reviewed_at"] = datetime.now().isoformat()
                    data[str(message_id)]["reviewed_by"] = admin_id
                    data[str(message_id)]["last_updated"] = datetime.now().isoformat()
                    
                    self.save_json(self.pending_verifications_file, data)
                    
                    # İstatistikleri güncelle
                    if status.startswith("rejected"):
                        self.update_statistics("total_rejected", 1)
                    
                    self.logger.info(f"Doğrulama durumu güncellendi: {message_id} -> {status}")
                    
        except Exception as e:
            self.logger.error(f"Doğrulama durumu güncelleme hatası: {str(e)}")
    
    def get_pending_verification(self, message_id: int) -> Optional[Dict]:
        """Bekleyen doğrulama bilgisi getir"""
        try:
            data = self.load_json(self.pending_verifications_file)
            return data.get(str(message_id))
        except Exception as e:
            self.logger.error(f"Bekleyen doğrulama alma hatası: {str(e)}")
            return None
    
    def cleanup_old_pending(self, days: int = 7):
        """Eski bekleyen doğrulamaları temizle"""
        try:
            with self.lock:
                data = self.load_json(self.pending_verifications_file)
                cutoff_date = datetime.now() - timedelta(days=days)
                
                cleaned_data = {}
                removed_count = 0
                
                for message_id, verification in data.items():
                    submitted_at = datetime.fromisoformat(verification["submitted_at"])
                    
                    if submitted_at > cutoff_date:
                        cleaned_data[message_id] = verification
                    else:
                        removed_count += 1
                
                if removed_count > 0:
                    self.save_json(self.pending_verifications_file, cleaned_data)
                    self.logger.info(f"Eski bekleyen doğrulamalar temizlendi: {removed_count} adet")
                
        except Exception as e:
            self.logger.error(f"Bekleyen doğrulama temizleme hatası: {str(e)}")
    
    # Kullanıcı deneme takibi
    def increment_user_attempts(self, user_id: int, username: str):
        """Kullanıcı deneme sayısını artır"""
        try:
            with self.lock:
                data = self.load_json(self.user_attempts_file)
                
                if str(user_id) not in data:
                    data[str(user_id)] = {
                        "username": username,
                        "total_attempts": 0,
                        "daily_attempts": {},
                        "first_attempt": datetime.now().isoformat(),
                        "last_attempt": None,
                        "suspicious_activity": False
                    }
                
                user_data = data[str(user_id)]
                user_data["total_attempts"] += 1
                user_data["last_attempt"] = datetime.now().isoformat()
                user_data["username"] = username  # Username güncellemesi
                
                # Günlük deneme sayısı
                today = datetime.now().strftime('%Y-%m-%d')
                if today not in user_data["daily_attempts"]:
                    user_data["daily_attempts"][today] = 0
                user_data["daily_attempts"][today] += 1
                
                # Şüpheli aktivite kontrolü
                if user_data["daily_attempts"][today] > 5:  # Günde 5'ten fazla deneme
                    user_data["suspicious_activity"] = True
                    self.log_security_event(user_id, "excessive_attempts", {
                        "daily_attempts": user_data["daily_attempts"][today],
                        "total_attempts": user_data["total_attempts"]
                    })
                
                self.save_json(self.user_attempts_file, data)
                self.update_statistics("total_attempts", 1)
                
        except Exception as e:
            self.logger.error(f"Kullanıcı deneme artırma hatası: {str(e)}", user_id=user_id)
    
    def get_user_attempt_count(self, user_id: int) -> int:
        """Kullanıcı toplam deneme sayısını getir"""
        try:
            data = self.load_json(self.user_attempts_file)
            return data.get(str(user_id), {}).get("total_attempts", 0)
        except Exception as e:
            self.logger.error(f"Kullanıcı deneme sayısı alma hatası: {str(e)}", user_id=user_id)
            return 0
    
    def get_user_daily_attempts(self, user_id: int) -> int:
        """Kullanıcı günlük deneme sayısını getir"""
        try:
            data = self.load_json(self.user_attempts_file)
            today = datetime.now().strftime('%Y-%m-%d')
            return data.get(str(user_id), {}).get("daily_attempts", {}).get(today, 0)
        except Exception as e:
            self.logger.error(f"Günlük deneme sayısı alma hatası: {str(e)}", user_id=user_id)
            return 0
    
    def is_user_suspicious(self, user_id: int) -> bool:
        """Kullanıcı şüpheli mi kontrol et"""
        try:
            data = self.load_json(self.user_attempts_file)
            return data.get(str(user_id), {}).get("suspicious_activity", False)
        except Exception as e:
            self.logger.error(f"Şüpheli kullanıcı kontrolü hatası: {str(e)}", user_id=user_id)
            return False
    
    def get_user_data(self, user_id: int) -> Dict:
        """Kapsamlı kullanıcı verisi getir"""
        try:
            # Doğrulanmış kullanıcı verisi
            verified_data = self.get_verified_user_data(user_id)
            
            # Deneme verisi
            attempts_data = self.load_json(self.user_attempts_file)
            attempt_info = attempts_data.get(str(user_id), {})
            
            # Bekleyen doğrulama verisi
            pending_data = self.load_json(self.pending_verifications_file)
            pending_verifications = [v for v in pending_data.values() if v.get("user_id") == user_id]
            
            return {
                "is_verified": verified_data is not None,
                "verification_data": verified_data,
                "attempts": attempt_info.get("total_attempts", 0),
                "daily_attempts": self.get_user_daily_attempts(user_id),
                "suspicious": attempt_info.get("suspicious_activity", False),
                "pending_verifications": len(pending_verifications),
                "last_verification": verified_data.get("verified_at") if verified_data else None,
                "security_score": verified_data.get("security_score", 100) if verified_data else 100,
                "first_attempt": attempt_info.get("first_attempt"),
                "last_attempt": attempt_info.get("last_attempt")
            }
            
        except Exception as e:
            self.logger.error(f"Kullanıcı veri alma hatası: {str(e)}", user_id=user_id)
            return {
                "is_verified": False,
                "attempts": 0,
                "daily_attempts": 0,
                "suspicious": False,
                "pending_verifications": 0
            }
    
    # İstatistik işlemleri
    def update_statistics(self, key: str, value: int):
        """İstatistik güncelle"""
        try:
            with self.lock:
                data = self.load_json(self.statistics_file)
                
                if key in data:
                    data[key] += value
                else:
                    data[key] = value
                
                data["last_updated"] = datetime.now().isoformat()
                self.save_json(self.statistics_file, data)
                
        except Exception as e:
            self.logger.error(f"İstatistik güncelleme hatası: {str(e)}")
    
    def get_statistics(self) -> Dict:
        """Kapsamlı istatistikler getir"""
        try:
            base_stats = self.load_json(self.statistics_file)
            
            # Güncel verilerden hesaplanan istatistikler
            verified_users = self.load_json(self.verified_users_file)
            pending_verifications = self.load_json(self.pending_verifications_file)
            user_attempts = self.load_json(self.user_attempts_file)
            
            # Bugünün tarihi
            today = datetime.now().strftime('%Y-%m-%d')
            
            # Bugün doğrulanmış kullanıcılar
            today_verified = 0
            for user_data in verified_users.values():
                if user_data.get("verified_at", "").startswith(today):
                    today_verified += 1
            
            # Bugün gelen istekler
            today_pending = 0
            for verification in pending_verifications.values():
                if verification.get("submitted_at", "").startswith(today):
                    today_pending += 1
            
            # Bugün reddedilen
            today_rejected = 0
            for verification in pending_verifications.values():
                if (verification.get("reviewed_at", "").startswith(today) and 
                    verification.get("status", "").startswith("rejected")):
                    today_rejected += 1
            
            # Şüpheli kullanıcılar
            suspicious_users = sum(1 for user in user_attempts.values() 
                                 if user.get("suspicious_activity", False))
            
            # Başarı oranı hesaplama
            total_attempts = base_stats.get("total_attempts", 0)
            total_verified = len(verified_users)
            success_rate = (total_verified / total_attempts * 100) if total_attempts > 0 else 0
            
            # Memory usage (basit hesaplama)
            import sys
            memory_usage = sys.getsizeof(verified_users) + sys.getsizeof(pending_verifications)
            memory_usage_mb = memory_usage / (1024 * 1024)
            
            return {
                **base_stats,
                "total_verified": len(verified_users),
                "total_pending": len([v for v in pending_verifications.values() 
                                    if v.get("status") == "pending"]),
                "today_verified": today_verified,
                "today_pending": today_pending,
                "today_rejected": today_rejected,
                "pending_requests": len(pending_verifications),
                "suspicious_users": suspicious_users,
                "success_rate": round(success_rate, 2),
                "memory_usage": round(memory_usage_mb, 2),
                "total_users_attempted": len(user_attempts),
                "database_health": "good"  # Basit health check
            }
            
        except Exception as e:
            self.logger.error(f"İstatistik alma hatası: {str(e)}")
            return {
                "total_verified": 0,
                "total_rejected": 0,
                "total_attempts": 0,
                "error": str(e)
            }
    
    # Güvenlik olayları
    def log_security_event(self, user_id: int, event_type: str, details: Dict):
        """Güvenlik olayı kaydet"""
        try:
            with self.lock:
                events = self.load_json(self.security_events_file, [])
                
                event = {
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.now().isoformat(),
                    "user_id": user_id,
                    "event_type": event_type,
                    "details": details,
                    "severity": self.get_event_severity(event_type),
                    "resolved": False
                }
                
                events.append(event)
                
                # Son 1000 olayı tut
                if len(events) > 1000:
                    events = events[-1000:]
                
                self.save_json(self.security_events_file, events)
                
                # İstatistik güncelle
                if event_type == "spam_attempt":
                    self.update_statistics("spam_blocked", 1)
                elif event_type == "duplicate_image":
                    self.update_statistics("duplicates_blocked", 1)
                
                self.logger.security(f"Güvenlik olayı: {event_type}", details, user_id)
                
        except Exception as e:
            self.logger.error(f"Güvenlik olayı kaydetme hatası: {str(e)}", user_id=user_id)
    
    def get_event_severity(self, event_type: str) -> str:
        """Olay şiddet seviyesi belirle"""
        severity_map = {
            "spam_attempt": "medium",
            "duplicate_image": "high",
            "excessive_attempts": "medium",
            "suspicious_activity": "high",
            "security_violation": "high",
            "rate_limit_exceeded": "low"
        }
        return severity_map.get(event_type, "low")
    
    def get_security_events(self, limit: int = 50, user_id: int = None) -> List[Dict]:
        """Güvenlik olaylarını getir"""
        try:
            events = self.load_json(self.security_events_file, [])
            
            # Kullanıcı filtresi
            if user_id:
                events = [e for e in events if e.get("user_id") == user_id]
            
            # Tarihe göre sırala (en yeni önce)
            events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            
            return events[:limit]
            
        except Exception as e:
            self.logger.error(f"Güvenlik olayları alma hatası: {str(e)}")
            return []
    
    # Admin aksiyonları
    def log_admin_action(self, admin_id: int, admin_name: str, action: str, 
                        target_user_id: int, target_username: str, details: Dict = None):
        """Admin aksiyonu kaydet"""
        try:
            with self.lock:
                actions = self.load_json(self.admin_actions_file, [])
                
                action_data = {
                    "id": str(uuid.uuid4()),
                    "timestamp": datetime.now().isoformat(),
                    "admin_id": admin_id,
                    "admin_name": admin_name,
                    "action": action,
                    "target_user_id": target_user_id,
                    "target_username": target_username,
                    "details": details or {},
                    "ip_hash": None  # Discord'dan IP alamıyoruz
                }
                
                actions.append(action_data)
                
                # Son 1000 aksiyonu tut
                if len(actions) > 1000:
                    actions = actions[-1000:]
                
                self.save_json(self.admin_actions_file, actions)
                
                self.logger.admin_action(admin_id, admin_name, action, target_username, details)
                
        except Exception as e:
            self.logger.error(f"Admin aksiyon kaydetme hatası: {str(e)}")
    
    def get_admin_actions(self, limit: int = 50, admin_id: int = None) -> List[Dict]:
        """Admin aksiyonlarını getir"""
        try:
            actions = self.load_json(self.admin_actions_file, [])
            
            # Admin filtresi
            if admin_id:
                actions = [a for a in actions if a.get("admin_id") == admin_id]
            
            # Tarihe göre sırala (en yeni önce)
            actions.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            
            return actions[:limit]
            
        except Exception as e:
            self.logger.error(f"Admin aksiyonları alma hatası: {str(e)}")
            return []
    
    # Veritabanı yönetimi
    def backup_database(self, backup_path: str = None) -> bool:
        """Veritabanı yedeği oluştur"""
        try:
            if not backup_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f"data/backup_{timestamp}"
            
            os.makedirs(backup_path, exist_ok=True)
            
            # Tüm dosyaları kopyala
            import shutil
            files_to_backup = [
                self.verified_users_file,
                self.pending_verifications_file,
                self.user_attempts_file,
                self.statistics_file,
                self.security_events_file,
                self.admin_actions_file
            ]
            
            for file_path in files_to_backup:
                if os.path.exists(file_path):
                    filename = os.path.basename(file_path)
                    shutil.copy2(file_path, os.path.join(backup_path, filename))
            
            # Backup bilgisi oluştur
            backup_info = {
                "created_at": datetime.now().isoformat(),
                "files_backed_up": len(files_to_backup),
                "total_verified_users": len(self.load_json(self.verified_users_file)),
                "backup_version": "1.0"
            }
            
            with open(os.path.join(backup_path, "backup_info.json"), 'w') as f:
                json.dump(backup_info, f, indent=2)
            
            self.logger.success(f"Veritabanı yedeği oluşturuldu: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Yedekleme hatası: {str(e)}")
            return False
    
    def restore_database(self, backup_path: str) -> bool:
        """Veritabanını yedekten geri yükle"""
        try:
            if not os.path.exists(backup_path):
                self.logger.error(f"Yedek klasörü bulunamadı: {backup_path}")
                return False
            
            # Mevcut veritabanını yedekle
            current_backup = f"data/before_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            self.backup_database(current_backup)
            
            # Yedekten dosyaları geri yükle
            import shutil
            files_to_restore = [
                "verified_users.json",
                "pending_verifications.json", 
                "user_attempts.json",
                "statistics.json",
                "security_events.json",
                "admin_actions.json"
            ]
            
            for filename in files_to_restore:
                backup_file = os.path.join(backup_path, filename)
                target_file = os.path.join(self.data_dir, filename)
                
                if os.path.exists(backup_file):
                    shutil.copy2(backup_file, target_file)
            
            self.logger.success(f"Veritabanı geri yüklendi: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Geri yükleme hatası: {str(e)}")
            return False
    
    def clean_all(self) -> bool:
        """Tüm veritabanını temizle"""
        try:
            with self.lock:
                # Tüm dosyaları sıfırla
                self.save_json(self.verified_users_file, {})
                self.save_json(self.pending_verifications_file, {})
                self.save_json(self.user_attempts_file, {})
                self.save_json(self.security_events_file, [])
                self.save_json(self.admin_actions_file, [])
                
                # İstatistikleri sıfırla
                self.save_json(self.statistics_file, {
                    "total_verified": 0,
                    "total_rejected": 0,
                    "total_attempts": 0,
                    "spam_blocked": 0,
                    "duplicates_blocked": 0,
                    "created_at": datetime.now().isoformat(),
                    "last_updated": datetime.now().isoformat()
                })
                
                self.logger.warning("Tüm veritabanı temizlendi!")
                return True
                
        except Exception as e:
            self.logger.error(f"Veritabanı temizleme hatası: {str(e)}")
            return False
    
    def test_connection(self) -> bool:
        """Veritabanı bağlantı testi"""
        try:
            # Basit okuma/yazma testi
            test_data = {"test": True, "timestamp": datetime.now().isoformat()}
            test_file = os.path.join(self.data_dir, "test.json")
            
            self.save_json(test_file, test_data)
            loaded_data = self.load_json(test_file)
            
            # Test dosyasını sil
            if os.path.exists(test_file):
                os.remove(test_file)
            
            return loaded_data.get("test") == True
            
        except Exception as e:
            self.logger.error(f"Veritabanı test hatası: {str(e)}")
            return False
    
    def get_database_info(self) -> Dict:
        """Veritabanı bilgilerini getir"""
        try:
            info = {
                "data_directory": self.data_dir,
                "files": {},
                "total_size_mb": 0,
                "last_backup": None,
                "health_status": "good"
            }
            
            # Dosya bilgileri
            files = [
                self.verified_users_file,
                self.pending_verifications_file,
                self.user_attempts_file,
                self.statistics_file,
                self.security_events_file,
                self.admin_actions_file
            ]
            
            for file_path in files:
                if os.path.exists(file_path):
                    file_size = os.path.getsize(file_path)
                    info["files"][os.path.basename(file_path)] = {
                        "size_bytes": file_size,
                        "size_mb": round(file_size / (1024*1024), 2),
                        "last_modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                    }
                    info["total_size_mb"] += file_size / (1024*1024)
            
            info["total_size_mb"] = round(info["total_size_mb"], 2)
            
            # Health check
            if not self.test_connection():
                info["health_status"] = "error"
            
            return info
            
        except Exception as e:
            self.logger.error(f"Veritabanı bilgi alma hatası: {str(e)}")
            return {"error": str(e)}