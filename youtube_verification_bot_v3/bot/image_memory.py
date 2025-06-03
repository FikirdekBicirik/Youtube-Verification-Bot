# bot/image_memory.py
import hashlib
import json
import os
import requests
from PIL import Image
import io
import imagehash
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import asyncio
from threading import Lock
import tempfile
import cv2
import numpy as np

from utils.logger import Logger
from utils.config import Config

class ImageMemory:
    """Gelişmiş resim hafızası ve duplicate tespit sistemi"""
    
    def __init__(self):
        self.logger = Logger()
        self.data_dir = "data"
        self.temp_dir = "data/temp"
        self.lock = Lock()
        
        # Dosya yolları
        self.image_memory_file = os.path.join(self.data_dir, "image_memory.json")
        self.hash_database_file = os.path.join(self.data_dir, "image_hashes.json")
        self.duplicate_log_file = os.path.join(self.data_dir, "duplicate_detections.json")
        
        # Hash algoritmalarının threshold değerleri
        self.hash_thresholds = {
            'dhash': 5,      # Perceptual hash - düşük threshold (daha hassas)
            'phash': 8,      # Perceptual hash - orta threshold
            'ahash': 10,     # Average hash - yüksek threshold (daha esnek)
            'whash': 6,      # Wavelet hash - düşük threshold
            'md5': 0,        # Exact match için
            'sha256': 0      # Exact match için
        }
        
        # Resim özellik eşikleri
        self.similarity_thresholds = {
            'identical': 0,      # Tamamen aynı
            'very_similar': 3,   # Çok benzer (crop, resize vs.)
            'similar': 8,        # Benzer
            'possibly_similar': 15  # Muhtemelen benzer
        }
        
        self.ensure_directories()
        self.load_memory()
    
    def ensure_directories(self):
        """Gerekli klasörleri oluştur"""
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.temp_dir, exist_ok=True)
        
        # Memory dosyalarını oluştur
        if not os.path.exists(self.image_memory_file):
            self.save_json(self.image_memory_file, {})
        
        if not os.path.exists(self.hash_database_file):
            self.save_json(self.hash_database_file, {})
        
        if not os.path.exists(self.duplicate_log_file):
            self.save_json(self.duplicate_log_file, [])
    
    def load_memory(self):
        """Hafızayı yükle"""
        try:
            self.logger.info("Resim hafızası yükleniyor...")
            
            # Eski kayıtları temizle (30 gün)
            self.cleanup_old_records(30)
            
            memory_data = self.load_json(self.image_memory_file)
            hash_data = self.load_json(self.hash_database_file)
            
            self.logger.info(f"Hafızaya yüklendi: {len(memory_data)} resim, {len(hash_data)} hash")
            
        except Exception as e:
            self.logger.error(f"Hafıza yükleme hatası: {str(e)}")
    
    def load_json(self, file_path: str, default: any = None) -> any:
        """JSON dosyası yükle"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return default or {}
        except Exception as e:
            self.logger.error(f"JSON yükleme hatası {file_path}: {str(e)}")
            return default or {}
    
    def save_json(self, file_path: str, data: any):
        """JSON dosyası kaydet"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"JSON kaydetme hatası {file_path}: {str(e)}")
    
    async def store_image(self, image_url: str, user_id: int, username: str, 
                         message_id: int, existing: bool = False) -> bool:
        """Resmi hafızaya kaydet ve hash'lerini hesapla"""
        try:
            with self.lock:
                self.logger.info(f"Resim hafızaya kaydediliyor: {username} ({user_id})", user_id=user_id)
                
                # Resmi indir
                image = await self.download_image(image_url)
                if not image:
                    return False
                
                # Tüm hash'leri hesapla
                image_hashes = self.calculate_all_hashes(image, image_url)
                
                # Resim özelliklerini çıkar
                image_features = self.extract_image_features(image)
                
                # Memory kaydı oluştur
                memory_record = {
                    "id": f"{user_id}_{message_id}",
                    "user_id": user_id,
                    "username": username,
                    "message_id": message_id,
                    "image_url": image_url,
                    "stored_at": datetime.now().isoformat(),
                    "existing_record": existing,
                    "hashes": image_hashes,
                    "features": image_features,
                    "file_size": len(await self.get_image_bytes(image_url)),
                    "dimensions": f"{image.width}x{image.height}",
                    "verified": False
                }
                
                # Ana hafızaya kaydet
                memory_data = self.load_json(self.image_memory_file)
                memory_data[memory_record["id"]] = memory_record
                self.save_json(self.image_memory_file, memory_data)
                
                # Hash veritabanına kaydet
                hash_data = self.load_json(self.hash_database_file)
                
                for hash_type, hash_value in image_hashes.items():
                    if hash_type not in hash_data:
                        hash_data[hash_type] = {}
                    
                    hash_data[hash_type][str(hash_value)] = {
                        "record_id": memory_record["id"],
                        "user_id": user_id,
                        "username": username,
                        "stored_at": memory_record["stored_at"]
                    }
                
                self.save_json(self.hash_database_file, hash_data)
                
                self.logger.success(f"Resim hafızaya kaydedildi: {memory_record['id']}", user_id=user_id)
                return True
                
        except Exception as e:
            self.logger.error(f"Resim kaydetme hatası: {str(e)}", user_id=user_id)
            return False
    
    async def check_duplicate(self, image_url: str) -> Optional[Dict]:
        """Duplicate resim kontrolü"""
        try:
            self.logger.info("Duplicate resim kontrolü yapılıyor")
            
            # Resmi indir
            image = await self.download_image(image_url)
            if not image:
                return None
            
            # Hash'leri hesapla
            new_hashes = self.calculate_all_hashes(image, image_url)
            
            # Hash veritabanından kontrol et
            hash_data = self.load_json(self.hash_database_file)
            
            # Farklı hash türleri ile kontrol
            duplicate_results = []
            
            for hash_type, new_hash_value in new_hashes.items():
                if hash_type in hash_data:
                    threshold = self.hash_thresholds.get(hash_type, 5)
                    
                    for stored_hash, hash_info in hash_data[hash_type].items():
                        similarity = self.calculate_hash_similarity(
                            hash_type, new_hash_value, stored_hash
                        )
                        
                        if similarity <= threshold:
                            duplicate_results.append({
                                'hash_type': hash_type,
                                'similarity_score': similarity,
                                'threshold': threshold,
                                'match_quality': self.get_match_quality(similarity),
                                'original_record': hash_info
                            })
            
            # En iyi eşleşmeyi bul
            if duplicate_results:
                best_match = min(duplicate_results, key=lambda x: x['similarity_score'])
                
                # Orijinal kayıt bilgilerini al
                memory_data = self.load_json(self.image_memory_file)
                original_record = memory_data.get(best_match['original_record']['record_id'])
                
                if original_record:
                    # Duplicate log'a kaydet
                    await self.log_duplicate_detection(image_url, original_record, best_match)
                    
                    return {
                        'is_duplicate': True,
                        'similarity_score': best_match['similarity_score'],
                        'match_quality': best_match['match_quality'],
                        'hash_type': best_match['hash_type'],
                        'username': original_record['username'],
                        'user_id': original_record['user_id'],
                        'timestamp': int(datetime.fromisoformat(original_record['stored_at']).timestamp()),
                        'original_url': original_record['image_url'],
                        'message_id': original_record['message_id']
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Duplicate kontrol hatası: {str(e)}")
            return None
    
    async def download_image(self, image_url: str) -> Optional[Image.Image]:
        """Resmi indir"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(image_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Maksimum dosya boyutu kontrolü (15MB)
            if len(response.content) > 15 * 1024 * 1024:
                self.logger.warning("Resim çok büyük, hafızaya kaydedilmiyor")
                return None
            
            image = Image.open(io.BytesIO(response.content))
            
            # RGB'ye çevir
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            return image
            
        except Exception as e:
            self.logger.error(f"Resim indirme hatası: {str(e)}")
            return None
    
    async def get_image_bytes(self, image_url: str) -> bytes:
        """Resmin byte'larını al"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(image_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            return response.content
            
        except Exception as e:
            self.logger.error(f"Resim byte alma hatası: {str(e)}")
            return b""
    
    def calculate_all_hashes(self, image: Image.Image, image_url: str) -> Dict[str, str]:
        """Tüm hash türlerini hesapla"""
        try:
            hashes = {}
            
            # Perceptual hashes (imagehash kütüphanesi)
            hashes['dhash'] = str(imagehash.dhash(image))
            hashes['phash'] = str(imagehash.phash(image))
            hashes['ahash'] = str(imagehash.average_hash(image))
            hashes['whash'] = str(imagehash.whash(image))
            
            # Cryptographic hashes
            image_bytes = io.BytesIO()
            image.save(image_bytes, format='PNG')
            image_data = image_bytes.getvalue()
            
            hashes['md5'] = hashlib.md5(image_data).hexdigest()
            hashes['sha256'] = hashlib.sha256(image_data).hexdigest()
            
            # Custom hash (resim özelliklerine dayalı)
            hashes['custom'] = self.calculate_custom_hash(image)
            
            return hashes
            
        except Exception as e:
            self.logger.error(f"Hash hesaplama hatası: {str(e)}")
            return {}
    
    def calculate_custom_hash(self, image: Image.Image) -> str:
        """Özel hash algoritması"""
        try:
            # Resmi küçült
            thumbnail = image.copy()
            thumbnail.thumbnail((32, 32), Image.LANCZOS)
            
            # Gri tonlamaya çevir
            gray = thumbnail.convert('L')
            
            # Histogram hesapla
            histogram = gray.histogram()
            
            # Ortalama parlaklık
            avg_brightness = sum(i * histogram[i] for i in range(256)) / sum(histogram)
            
            # Standart sapma hesapla
            variance = sum(histogram[i] * (i - avg_brightness) ** 2 for i in range(256)) / sum(histogram)
            std_dev = variance ** 0.5
            
            # Edge detection
            cv_image = cv2.cvtColor(np.array(thumbnail), cv2.COLOR_RGB2BGR)
            gray_cv = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            edges = cv2.Canny(gray_cv, 50, 150)
            edge_ratio = np.sum(edges > 0) / (edges.shape[0] * edges.shape[1])
            
            # Custom hash oluştur
            custom_data = f"{image.width}x{image.height}_{avg_brightness:.2f}_{std_dev:.2f}_{edge_ratio:.4f}"
            custom_hash = hashlib.md5(custom_data.encode()).hexdigest()[:16]
            
            return custom_hash
            
        except Exception as e:
            self.logger.error(f"Custom hash hatası: {str(e)}")
            return "error"
    
    def extract_image_features(self, image: Image.Image) -> Dict[str, any]:
        """Resim özelliklerini çıkar"""
        try:
            features = {
                'width': image.width,
                'height': image.height,
                'aspect_ratio': round(image.width / image.height, 3),
                'total_pixels': image.width * image.height,
                'format': image.format or 'unknown'
            }
            
            # Renk analizi
            colors = image.getcolors(maxcolors=256*256*256)
            if colors:
                features['unique_colors'] = len(colors)
                features['dominant_color'] = max(colors, key=lambda x: x[0])[1][:3]  # RGB
            
            # Histogram özellikleri
            histogram = image.histogram()
            if len(histogram) >= 256:
                features['brightness_avg'] = sum(i * histogram[i] for i in range(256)) / sum(histogram[:256])
                features['brightness_std'] = (sum(histogram[i] * (i - features['brightness_avg']) ** 2 
                                                for i in range(256)) / sum(histogram[:256])) ** 0.5
            
            # Compression artifacts detection (JPEG quality estimation)
            if hasattr(image, '_getexif') and image.format == 'JPEG':
                # JPEG quality estimation (simplified)
                temp_buffer = io.BytesIO()
                image.save(temp_buffer, format='JPEG', quality=95)
                high_quality_size = len(temp_buffer.getvalue())
                
                temp_buffer = io.BytesIO()
                image.save(temp_buffer, format='JPEG', quality=50)
                low_quality_size = len(temp_buffer.getvalue())
                
                # Estimate original quality
                current_buffer = io.BytesIO()
                image.save(current_buffer, format='JPEG')
                current_size = len(current_buffer.getvalue())
                
                if high_quality_size > 0:
                    quality_ratio = current_size / high_quality_size
                    features['estimated_jpeg_quality'] = min(100, max(10, quality_ratio * 100))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Özellik çıkarma hatası: {str(e)}")
            return {}
    
    def calculate_hash_similarity(self, hash_type: str, hash1: str, hash2: str) -> int:
        """İki hash arasındaki benzerliği hesapla"""
        try:
            if hash_type in ['md5', 'sha256', 'custom']:
                # Exact match için
                return 0 if hash1 == hash2 else 999
            
            elif hash_type in ['dhash', 'phash', 'ahash', 'whash']:
                # Hamming distance for perceptual hashes
                if len(hash1) != len(hash2):
                    return 999
                
                distance = sum(c1 != c2 for c1, c2 in zip(hash1, hash2))
                return distance
            
            else:
                return 999
                
        except Exception as e:
            self.logger.error(f"Hash benzerlik hesaplama hatası: {str(e)}")
            return 999
    
    def get_match_quality(self, similarity_score: int) -> str:
        """Benzerlik skoruna göre kalite seviyesi"""
        if similarity_score <= self.similarity_thresholds['identical']:
            return 'identical'
        elif similarity_score <= self.similarity_thresholds['very_similar']:
            return 'very_similar'
        elif similarity_score <= self.similarity_thresholds['similar']:
            return 'similar'
        elif similarity_score <= self.similarity_thresholds['possibly_similar']:
            return 'possibly_similar'
        else:
            return 'different'
    
    async def log_duplicate_detection(self, new_image_url: str, original_record: Dict, match_info: Dict):
        """Duplicate tespit logunu kaydet"""
        try:
            with self.lock:
                duplicate_logs = self.load_json(self.duplicate_log_file, [])
                
                log_entry = {
                    'id': f"dup_{int(datetime.now().timestamp())}",
                    'detected_at': datetime.now().isoformat(),
                    'new_image_url': new_image_url,
                    'original_record_id': original_record['id'],
                    'original_user_id': original_record['user_id'],
                    'original_username': original_record['username'],
                    'original_stored_at': original_record['stored_at'],
                    'match_info': match_info,
                    'action_taken': 'blocked'
                }
                
                duplicate_logs.append(log_entry)
                
                # Son 1000 kaydı tut
                if len(duplicate_logs) > 1000:
                    duplicate_logs = duplicate_logs[-1000:]
                
                self.save_json(self.duplicate_log_file, duplicate_logs)
                
                self.logger.security(
                    f"Duplicate resim tespit edildi",
                    extra_data={
                        'similarity_score': match_info['similarity_score'],
                        'match_quality': match_info['match_quality'],
                        'original_user': original_record['username']
                    }
                )
                
        except Exception as e:
            self.logger.error(f"Duplicate log kaydetme hatası: {str(e)}")
    
    def get_user_image_history(self, user_id: int) -> List[Dict]:
        """Kullanıcının resim geçmişi"""
        try:
            memory_data = self.load_json(self.image_memory_file)
            
            user_images = []
            for record_id, record in memory_data.items():
                if record.get('user_id') == user_id:
                    user_images.append({
                        'record_id': record_id,
                        'stored_at': record['stored_at'],
                        'image_url': record['image_url'],
                        'dimensions': record.get('dimensions', 'unknown'),
                        'verified': record.get('verified', False),
                        'message_id': record.get('message_id')
                    })
            
            # Tarihe göre sırala (en yeni önce)
            user_images.sort(key=lambda x: x['stored_at'], reverse=True)
            
            return user_images
            
        except Exception as e:
            self.logger.error(f"Kullanıcı resim geçmişi hatası: {str(e)}", user_id=user_id)
            return []
    
    def get_duplicate_statistics(self) -> Dict[str, any]:
        """Duplicate istatistikleri"""
        try:
            duplicate_logs = self.load_json(self.duplicate_log_file, [])
            memory_data = self.load_json(self.image_memory_file)
            
            # Temel istatistikler
            total_duplicates = len(duplicate_logs)
            total_images = len(memory_data)
            
            # Son 24 saat
            yesterday = datetime.now() - timedelta(days=1)
            recent_duplicates = [
                log for log in duplicate_logs 
                if datetime.fromisoformat(log['detected_at']) > yesterday
            ]
            
            # Hash türü dağılımı
            hash_type_distribution = {}
            for log in duplicate_logs:
                hash_type = log.get('match_info', {}).get('hash_type', 'unknown')
                hash_type_distribution[hash_type] = hash_type_distribution.get(hash_type, 0) + 1
            
            # Kalite dağılımı
            quality_distribution = {}
            for log in duplicate_logs:
                quality = log.get('match_info', {}).get('match_quality', 'unknown')
                quality_distribution[quality] = quality_distribution.get(quality, 0) + 1
            
            return {
                'total_duplicates': total_duplicates,
                'total_images': total_images,
                'duplicate_rate': round((total_duplicates / total_images * 100), 2) if total_images > 0 else 0,
                'recent_duplicates_24h': len(recent_duplicates),
                'hash_type_distribution': hash_type_distribution,
                'quality_distribution': quality_distribution,
                'last_duplicate': duplicate_logs[-1]['detected_at'] if duplicate_logs else None
            }
            
        except Exception as e:
            self.logger.error(f"Duplicate istatistik hatası: {str(e)}")
            return {}
    
    def cleanup_old_records(self, days: int = 30):
        """Eski kayıtları temizle"""
        try:
            with self.lock:
                cutoff_date = datetime.now() - timedelta(days=days)
                
                # Memory temizliği
                memory_data = self.load_json(self.image_memory_file)
                cleaned_memory = {}
                removed_memory_count = 0
                
                for record_id, record in memory_data.items():
                    stored_at = datetime.fromisoformat(record['stored_at'])
                    if stored_at > cutoff_date:
                        cleaned_memory[record_id] = record
                    else:
                        removed_memory_count += 1
                
                if removed_memory_count > 0:
                    self.save_json(self.image_memory_file, cleaned_memory)
                
                # Hash veritabanı temizliği
                hash_data = self.load_json(self.hash_database_file)
                cleaned_hashes = {}
                
                for hash_type, hash_records in hash_data.items():
                    cleaned_hashes[hash_type] = {}
                    for hash_value, hash_info in hash_records.items():
                        if hash_info['record_id'] in cleaned_memory:
                            cleaned_hashes[hash_type][hash_value] = hash_info
                
                self.save_json(self.hash_database_file, cleaned_hashes)
                
                # Duplicate log temizliği
                duplicate_logs = self.load_json(self.duplicate_log_file, [])
                cleaned_logs = [
                    log for log in duplicate_logs 
                    if datetime.fromisoformat(log['detected_at']) > cutoff_date
                ]
                
                removed_log_count = len(duplicate_logs) - len(cleaned_logs)
                if removed_log_count > 0:
                    self.save_json(self.duplicate_log_file, cleaned_logs)
                
                if removed_memory_count > 0 or removed_log_count > 0:
                    self.logger.info(f"Eski kayıtlar temizlendi: {removed_memory_count} resim, {removed_log_count} log")
                
        except Exception as e:
            self.logger.error(f"Kayıt temizleme hatası: {str(e)}")
    
    def mark_image_as_verified(self, record_id: str) -> bool:
        """Resmi doğrulanmış olarak işaretle"""
        try:
            with self.lock:
                memory_data = self.load_json(self.image_memory_file)
                
                if record_id in memory_data:
                    memory_data[record_id]['verified'] = True
                    memory_data[record_id]['verified_at'] = datetime.now().isoformat()
                    self.save_json(self.image_memory_file, memory_data)
                    
                    self.logger.info(f"Resim doğrulanmış olarak işaretlendi: {record_id}")
                    return True
                else:
                    self.logger.warning(f"Doğrulanacak resim kaydı bulunamadı: {record_id}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Resim doğrulama işaretleme hatası: {str(e)}")
            return False
    
    def search_similar_images(self, image_url: str, similarity_threshold: int = 10) -> List[Dict]:
        """Benzer resimleri ara"""
        try:
            # Resmi indir ve hash'lerini hesapla
            image = asyncio.run(self.download_image(image_url))
            if not image:
                return []
            
            search_hashes = self.calculate_all_hashes(image, image_url)
            hash_data = self.load_json(self.hash_database_file)
            memory_data = self.load_json(self.image_memory_file)
            
            similar_images = []
            
            # Her hash türü için ara
            for hash_type, search_hash in search_hashes.items():
                if hash_type in hash_data:
                    for stored_hash, hash_info in hash_data[hash_type].items():
                        similarity = self.calculate_hash_similarity(hash_type, search_hash, stored_hash)
                        
                        if similarity <= similarity_threshold:
                            record = memory_data.get(hash_info['record_id'])
                            if record:
                                similar_images.append({
                                    'record_id': hash_info['record_id'],
                                    'similarity_score': similarity,
                                    'hash_type': hash_type,
                                    'match_quality': self.get_match_quality(similarity),
                                    'user_id': record['user_id'],
                                    'username': record['username'],
                                    'stored_at': record['stored_at'],
                                    'image_url': record['image_url']
                                })
            
            # Benzersiz sonuçları al ve skoruna göre sırala
            unique_results = {}
            for result in similar_images:
                record_id = result['record_id']
                if record_id not in unique_results or result['similarity_score'] < unique_results[record_id]['similarity_score']:
                    unique_results[record_id] = result
            
            sorted_results = sorted(unique_results.values(), key=lambda x: x['similarity_score'])
            
            return sorted_results[:20]  # En fazla 20 sonuç döndür
            
        except Exception as e:
            self.logger.error(f"Benzer resim arama hatası: {str(e)}")
            return []
    
    def get_memory_info(self) -> Dict[str, any]:
        """Hafıza bilgilerini getir"""
        try:
            memory_data = self.load_json(self.image_memory_file)
            hash_data = self.load_json(self.hash_database_file)
            duplicate_logs = self.load_json(self.duplicate_log_file, [])
            
            # Dosya boyutları
            memory_file_size = os.path.getsize(self.image_memory_file) if os.path.exists(self.image_memory_file) else 0
            hash_file_size = os.path.getsize(self.hash_database_file) if os.path.exists(self.hash_database_file) else 0
            
            return {
                'total_images': len(memory_data),
                'total_hashes': sum(len(hashes) for hashes in hash_data.values()),
                'total_duplicates': len(duplicate_logs),
                'memory_file_size_mb': round(memory_file_size / (1024*1024), 2),
                'hash_file_size_mb': round(hash_file_size / (1024*1024), 2),
                'hash_types': list(hash_data.keys()),
                'oldest_record': min([r['stored_at'] for r in memory_data.values()]) if memory_data else None,
                'newest_record': max([r['stored_at'] for r in memory_data.values()]) if memory_data else None,
                'verified_images': len([r for r in memory_data.values() if r.get('verified', False)]),
                'status': 'active'
            }
            
        except Exception as e:
            self.logger.error(f"Hafıza bilgi alma hatası: {str(e)}")
            return {'status': 'error', 'error': str(e)}
    
    def test_system(self) -> bool:
        """Hafıza sistemi testi"""
        try:
            # Test resmi oluştur
            test_image = Image.new('RGB', (100, 100), color='red')
            
            # Hash hesaplama testi
            hashes = self.calculate_all_hashes(test_image, 'test_url')
            
            # Özellik çıkarma testi
            features = self.extract_image_features(test_image)
            
            # Temel kontroller
            return (
                len(hashes) > 0 and
                len(features) > 0 and
                'dhash' in hashes and
                'width' in features
            )
            
        except Exception as e:
            self.logger.error(f"Hafıza sistemi test hatası: {str(e)}")
            return False
    
    def export_memory_data(self, output_file: str, include_hashes: bool = False):
        """Hafıza verilerini dışa aktar"""
        try:
            memory_data = self.load_json(self.image_memory_file)
            duplicate_logs = self.load_json(self.duplicate_log_file, [])
            
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'total_images': len(memory_data),
                'total_duplicates': len(duplicate_logs),
                'images': memory_data,
                'duplicate_logs': duplicate_logs
            }
            
            if include_hashes:
                hash_data = self.load_json(self.hash_database_file)
                export_data['hashes'] = hash_data
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            self.logger.success(f"Hafıza verileri dışa aktarıldı: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Hafıza verisi dışa aktarma hatası: {str(e)}")