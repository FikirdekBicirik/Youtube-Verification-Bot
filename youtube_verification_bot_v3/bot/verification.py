# bot/verification.py
import re
import requests
from PIL import Image, ImageEnhance, ImageFilter
import io
import cv2
import numpy as np
from typing import Tuple, Dict, List, Optional
import logging
from datetime import datetime
import asyncio
import hashlib
import base64

from utils.logger import Logger
from utils.config import Config
from .ocr_engine import OCREngine

class AdvancedYouTubeVerification:
    """Gelişmiş YouTube doğrulama sistemi"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger()
        self.ocr = OCREngine(config)
        
        # Doğrulama ayarları
        self.min_width = 800
        self.min_height = 600
        self.max_file_size = config.get('MAX_FILE_SIZE', 15728640)  # 15MB
        
        # YouTube renk aralıkları (HSV)
        self.youtube_colors = {
            'subscribe_button_red': {
                'lower': np.array([0, 120, 120]),
                'upper': np.array([10, 255, 255])
            },
            'subscribed_button_gray': {
                'lower': np.array([0, 0, 100]),
                'upper': np.array([180, 30, 180])
            },
            'like_button_blue': {
                'lower': np.array([100, 150, 150]),
                'upper': np.array([130, 255, 255])
            },
            'youtube_red': {
                'lower': np.array([0, 150, 150]),
                'upper': np.array([10, 255, 255])
            }
        }
        
        # Kanal göstergeleri
        self.channel_indicators = self.config.get_youtube_indicators()
        
    async def verify_screenshot(self, image_url: str, user_id: int) -> Tuple[bool, Dict]:
        """Ana doğrulama fonksiyonu"""
        try:
            self.logger.info(f"Doğrulama başlatıldı", user_id=user_id)
            
            # 1. Resmi indir ve doğrula
            image = await self.download_and_validate_image(image_url)
            if not image:
                return False, {
                    'error': 'image_download_failed',
                    'confidence': 0,
                    'details': {'stage': 'download', 'issue': 'Resim indirilemedi veya geçersiz'}
                }
            
            # 2. Resim ön işleme
            processed_image = self.preprocess_image(image)
            
            # 3. OCR ile metin çıkarma
            extracted_text = await self.ocr.extract_text_advanced(processed_image)
            if not extracted_text:
                return False, {
                    'error': 'ocr_failed',
                    'confidence': 0,
                    'details': {'stage': 'ocr', 'issue': 'Resimden metin okunamadı'}
                }
            
            self.logger.debug(f"OCR sonucu: {extracted_text[:200]}...", user_id=user_id)
            
            # 4. YouTube platform kontrolü
            platform_check = self.verify_youtube_platform(extracted_text, processed_image)
            if not platform_check['is_youtube']:
                return False, {
                    'error': 'not_youtube',
                    'confidence': 0,
                    'details': platform_check
                }
            
            # 5. Kanal kontrolü (EN ÖNEMLİ)
            channel_check = await self.verify_channel_match(extracted_text, processed_image)
            if not channel_check['is_correct_channel']:
                return False, {
                    'error': 'wrong_channel',
                    'confidence': channel_check.get('confidence', 0),
                    'detected_channel': channel_check.get('detected_channel'),
                    'expected_channel': self.config.get('YOUR_CHANNEL_NAME'),
                    'details': channel_check
                }
            
            # 6. UI element analizi
            ui_analysis = await self.analyze_youtube_ui(processed_image, extracted_text)
            
            # 7. Gereksinim kontrolleri
            requirements_check = await self.check_all_requirements(
                extracted_text, ui_analysis, processed_image
            )
            
            # 8. Final skor hesaplama
            final_result = self.calculate_final_score({
                'platform_check': platform_check,
                'channel_check': channel_check,
                'ui_analysis': ui_analysis,
                'requirements_check': requirements_check,
                'extracted_text': extracted_text,
                'image_quality': self.assess_image_quality(image)
            })
            
            # Log
            self.logger.verification_attempt(
                user_id, "unknown",
                'success' if final_result['is_valid'] else 'failed',
                final_result['confidence'],
                final_result
            )
            
            return final_result['is_valid'], final_result
            
        except Exception as e:
            self.logger.error(f"Doğrulama hatası: {str(e)}", user_id=user_id)
            return False, {
                'error': str(e),
                'confidence': 0,
                'details': {'stage': 'unknown', 'exception': str(e)}
            }
    
    async def download_and_validate_image(self, image_url: str) -> Optional[Image.Image]:
        """Resmi indir ve temel doğrulamaları yap"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Timeout ile resmi indir
            response = requests.get(image_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            # Boyut kontrolü
            if len(response.content) > self.max_file_size:
                self.logger.warning(f"Resim çok büyük: {len(response.content)} bytes")
                return None
            
            # PIL Image'e çevir
            image = Image.open(io.BytesIO(response.content))
            
            # Boyut kontrolü
            width, height = image.size
            if width < self.min_width or height < self.min_height:
                self.logger.warning(f"Resim çok küçük: {width}x{height}")
                return None
            
            # Format kontrolü
            if image.format not in ['PNG', 'JPEG', 'JPG', 'WEBP', 'GIF']:
                self.logger.warning(f"Desteklenmeyen format: {image.format}")
                return None
            
            # RGB'ye çevir
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            return image
            
        except Exception as e:
            self.logger.error(f"Resim indirme hatası: {str(e)}")
            return None
    
    def preprocess_image(self, image: Image.Image) -> Image.Image:
        """Resim ön işleme"""
        try:
            # Kontrastı artır
            enhancer = ImageEnhance.Contrast(image)
            image = enhancer.enhance(1.2)
            
            # Keskinliği artır
            enhancer = ImageEnhance.Sharpness(image)
            image = enhancer.enhance(1.1)
            
            # Parlaklığı ayarla
            enhancer = ImageEnhance.Brightness(image)
            image = enhancer.enhance(1.05)
            
            return image
            
        except Exception as e:
            self.logger.error(f"Ön işleme hatası: {str(e)}")
            return image
    
    def verify_youtube_platform(self, text: str, image: Image.Image) -> Dict:
        """YouTube platformu kontrolü"""
        text_lower = text.lower()
        
        # YouTube göstergeleri
        youtube_indicators = [
            'youtube', 'youtube.com', 'youtu.be',
            'subscribe', 'abone ol', 'subscribers', 'aboneler',
            'like', 'beğen', 'dislike', 'beğenme',
            'share', 'paylaş', 'comment', 'yorum',
            'views', 'izlenme', 'görüntülenme'
        ]
        
        found_indicators = []
        for indicator in youtube_indicators:
            if indicator in text_lower:
                found_indicators.append(indicator)
        
        # Görsel YouTube kontrolü
        visual_score = self.detect_youtube_visual_elements(image)
        
        # Skor hesaplama
        text_score = min(len(found_indicators) * 15, 70)  # Max 70 puan
        total_score = text_score + visual_score
        
        is_youtube = total_score >= 50
        
        return {
            'is_youtube': is_youtube,
            'confidence': min(total_score, 100),
            'found_indicators': found_indicators,
            'text_score': text_score,
            'visual_score': visual_score,
            'details': f"Tespit edilen göstergeler: {', '.join(found_indicators[:5])}"
        }
    
    def detect_youtube_visual_elements(self, image: Image.Image) -> int:
        """YouTube görsel elementlerini tespit et"""
        try:
            # OpenCV'ye çevir
            cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            hsv = cv2.cvtColor(cv_image, cv2.COLOR_BGR2HSV)
            
            score = 0
            
            # YouTube kırmızısı tespit et
            red_mask = cv2.inRange(hsv, self.youtube_colors['youtube_red']['lower'], 
                                  self.youtube_colors['youtube_red']['upper'])
            red_pixels = cv2.countNonZero(red_mask)
            
            if red_pixels > 1000:  # Yeterli kırmızı piksel
                score += 20
            
            # Subscribe butonu rengi
            subscribe_mask = cv2.inRange(hsv, self.youtube_colors['subscribe_button_red']['lower'],
                                       self.youtube_colors['subscribe_button_red']['upper'])
            subscribe_pixels = cv2.countNonZero(subscribe_mask)
            
            if subscribe_pixels > 500:
                score += 15
            
            # Genel UI layout kontrolü
            gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            edges = cv2.Canny(gray, 50, 150)
            
            # Çok fazla edge varsa muhtemelen UI
            edge_ratio = cv2.countNonZero(edges) / (image.width * image.height)
            if 0.1 < edge_ratio < 0.4:  # Optimal UI edge oranı
                score += 10
            
            return min(score, 30)  # Max 30 puan
            
        except Exception as e:
            self.logger.error(f"Görsel element tespit hatası: {str(e)}")
            return 0
    
    async def verify_channel_match(self, text: str, image: Image.Image) -> Dict:
        """Kanal eşleşmesi kontrolü"""
        text_lower = text.lower()
        expected_channel = self.config.get('YOUR_CHANNEL_NAME', '').lower()
        
        if not expected_channel:
            return {
                'is_correct_channel': False,
                'confidence': 0,
                'error': 'Hedef kanal adı ayarlanmamış'
            }
        
        # Tam eşleşme kontrolü
        if expected_channel in text_lower:
            return {
                'is_correct_channel': True,
                'match_type': 'exact',
                'confidence': 95,
                'detected_channel': self.config.get('YOUR_CHANNEL_NAME'),
                'match_position': text_lower.find(expected_channel)
            }
        
        # Kısmi eşleşme kontrolü
        channel_words = expected_channel.split()
        matched_words = 0
        total_words = len(channel_words)
        
        for word in channel_words:
            if len(word) > 2 and word in text_lower:
                matched_words += 1
        
        match_ratio = matched_words / total_words if total_words > 0 else 0
        
        if match_ratio >= 0.7:  # %70 eşleşme
            return {
                'is_correct_channel': True,
                'match_type': 'partial',
                'confidence': int(match_ratio * 85),
                'detected_channel': self.config.get('YOUR_CHANNEL_NAME'),
                'matched_words': matched_words,
                'total_words': total_words
            }
        
        # Diğer kanal isimlerini tespit et
        detected_channels = self.detect_other_channels(text_lower)
        
        return {
            'is_correct_channel': False,
            'match_type': 'none',
            'confidence': 0,
            'detected_channel': detected_channels[0] if detected_channels else 'Tespit edilemedi',
            'other_channels': detected_channels,
            'expected_channel': self.config.get('YOUR_CHANNEL_NAME')
        }
    
    def detect_other_channels(self, text: str) -> List[str]:
        """Metindeki diğer kanal isimlerini tespit et"""
        patterns = [
            r'@(\w+)',  # @kullaniciadi
            r'(\w+)\s*•\s*\d+[KMB]?\s*(subscriber|abone)',  # KanalAdı • 1M subscribers
            r'(\w+)\s+(\d+[KMB]?\s*(subscriber|abone))',  # KanalAdı 1M subscribers
            r'(\w{3,20})\s*\|\s*YouTube',  # KanalAdı | YouTube
        ]
        
        detected = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    channel_name = match[0]
                else:
                    channel_name = match
                
                # Filtreleme
                if (len(channel_name) > 2 and 
                    channel_name.lower() not in ['youtube', 'google', 'video', 'music']):
                    detected.append(channel_name)
        
        return list(set(detected))[:3]  # İlk 3 benzersiz tespit
    
    async def analyze_youtube_ui(self, image: Image.Image, text: str) -> Dict:
        """YouTube UI elementlerini detaylı analiz et"""
        try:
            cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            
            ui_elements = {
                'subscribe_button': await self.detect_subscribe_button(cv_image, text),
                'like_button': await self.detect_like_button(cv_image, text),
                'comment_section': await self.detect_comment_section(cv_image, text),
                'video_player': await self.detect_video_player(cv_image),
                'navigation_bar': await self.detect_navigation_bar(cv_image, text),
                'channel_info': await self.detect_channel_info(cv_image, text)
            }
            
            # UI güvenilirlik skoru
            detected_count = sum(1 for element in ui_elements.values() 
                               if element.get('detected', False))
            ui_confidence = (detected_count / len(ui_elements)) * 100
            
            return {
                'elements': ui_elements,
                'ui_confidence': ui_confidence,
                'is_valid_youtube_ui': ui_confidence >= 60,
                'detected_elements': detected_count,
                'total_elements': len(ui_elements)
            }
            
        except Exception as e:
            self.logger.error(f"UI analiz hatası: {str(e)}")
            return {
                'elements': {},
                'ui_confidence': 0,
                'is_valid_youtube_ui': False,
                'error': str(e)
            }
    
    async def detect_subscribe_button(self, cv_image: np.ndarray, text: str) -> Dict:
        """Abone ol butonunu tespit et"""
        result = {
            'detected': False,
            'status': 'unknown',
            'confidence': 0,
            'method': 'none'
        }
        
        text_lower = text.lower()
        
        # Metin tabanlı tespit
        subscribe_patterns = [
            (r'abone\s+olundu', 'subscribed', 95),
            (r'subscribed', 'subscribed', 90),
            (r'abone\s+ol', 'not_subscribed', 85),
            (r'subscribe', 'not_subscribed', 80),
        ]
        
        for pattern, status, confidence in subscribe_patterns:
            if re.search(pattern, text_lower):
                result.update({
                    'detected': True,
                    'status': status,
                    'confidence': confidence,
                    'method': 'text_recognition'
                })
                return result
        
        # Renk tabanlı tespit
        hsv = cv2.cvtColor(cv_image, cv2.COLOR_BGR2HSV)
        
        # Kırmızı buton (subscribe)
        red_mask = cv2.inRange(hsv, self.youtube_colors['subscribe_button_red']['lower'],
                              self.youtube_colors['subscribe_button_red']['upper'])
        red_area = cv2.countNonZero(red_mask)
        
        # Gri buton (subscribed)
        gray_mask = cv2.inRange(hsv, self.youtube_colors['subscribed_button_gray']['lower'],
                               self.youtube_colors['subscribed_button_gray']['upper'])
        gray_area = cv2.countNonZero(gray_mask)
        
        if gray_area > red_area and gray_area > 500:
            result.update({
                'detected': True,
                'status': 'subscribed',
                'confidence': 70,
                'method': 'color_analysis'
            })
        elif red_area > 500:
            result.update({
                'detected': True,
                'status': 'not_subscribed',
                'confidence': 65,
                'method': 'color_analysis'
            })
        
        return result
    
    async def detect_like_button(self, cv_image: np.ndarray, text: str) -> Dict:
        """Beğeni butonunu tespit et"""
        result = {
            'detected': False,
            'status': 'unknown',
            'confidence': 0,
            'method': 'none'
        }
        
        text_lower = text.lower()
        
        # Metin tabanlı tespit
        like_patterns = [
            (r'beğendin', 'liked', 95),
            (r'liked', 'liked', 90),
            (r'beğen', 'not_liked', 75),
            (r'like', 'not_liked', 70),
        ]
        
        for pattern, status, confidence in like_patterns:
            if re.search(pattern, text_lower):
                result.update({
                    'detected': True,
                    'status': status,
                    'confidence': confidence,
                    'method': 'text_recognition'
                })
                return result
        
        # Mavi renk tespit (beğenilmiş buton)
        hsv = cv2.cvtColor(cv_image, cv2.COLOR_BGR2HSV)
        blue_mask = cv2.inRange(hsv, self.youtube_colors['like_button_blue']['lower'],
                               self.youtube_colors['like_button_blue']['upper'])
        blue_area = cv2.countNonZero(blue_mask)
        
        if blue_area > 300:  # Yeterli mavi alan
            result.update({
                'detected': True,
                'status': 'liked',
                'confidence': 75,
                'method': 'color_analysis'
            })
        
        return result
    
    async def detect_comment_section(self, cv_image: np.ndarray, text: str) -> Dict:
        """Yorum bölümünü tespit et"""
        text_lower = text.lower()
        
        comment_indicators = [
            'yorum', 'comment', 'comments', 'yorumlar',
            'yanıtla', 'reply', 'replies', 'cevapla'
        ]
        
        found_indicators = [ind for ind in comment_indicators if ind in text_lower]
        
        if found_indicators:
            return {
                'detected': True,
                'confidence': min(len(found_indicators) * 25, 90),
                'method': 'text_recognition',
                'indicators': found_indicators
            }
        
        return {
            'detected': False,
            'confidence': 0,
            'method': 'none'
        }
    
    async def detect_video_player(self, cv_image: np.ndarray) -> Dict:
        """Video player'ı tespit et"""
        try:
            gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
            
            # Büyük siyah alanları tespit et (video player)
            black_mask = cv2.inRange(gray, 0, 30)
            contours, _ = cv2.findContours(black_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            total_area = cv_image.shape[0] * cv_image.shape[1]
            
            for contour in contours:
                area = cv2.contourArea(contour)
                area_ratio = area / total_area
                
                # Video player genellikle ekranın %20-60'ını kaplar
                if 0.2 <= area_ratio <= 0.6:
                    return {
                        'detected': True,
                        'confidence': 80,
                        'method': 'area_detection',
                        'area_ratio': area_ratio
                    }
            
            return {
                'detected': False,
                'confidence': 0,
                'method': 'area_detection'
            }
            
        except Exception as e:
            return {
                'detected': False,
                'confidence': 0,
                'error': str(e)
            }
    
    async def detect_navigation_bar(self, cv_image: np.ndarray, text: str) -> Dict:
        """YouTube navigasyon çubuğunu tespit et"""
        text_lower = text.lower()
        
        nav_indicators = [
            'ana sayfa', 'home', 'trending', 'keşfet',
            'explore', 'subscriptions', 'abonelikler',
            'library', 'kitaplık', 'geçmiş', 'history'
        ]
        
        found_nav = [ind for ind in nav_indicators if ind in text_lower]
        
        if found_nav:
            return {
                'detected': True,
                'confidence': min(len(found_nav) * 20, 85),
                'method': 'text_recognition',
                'indicators': found_nav
            }
        
        return {
            'detected': False,
            'confidence': 0
        }
    
    async def detect_channel_info(self, cv_image: np.ndarray, text: str) -> Dict:
        """Kanal bilgi bölümünü tespit et"""
        text_lower = text.lower()
        
        channel_indicators = [
            'subscribers', 'aboneler', 'abone',
            'videos', 'videolar', 'video',
            'joined', 'katıldı', 'üye oldu'
        ]
        
        found_indicators = [ind for ind in channel_indicators if ind in text_lower]
        
        if found_indicators:
            return {
                'detected': True,
                'confidence': min(len(found_indicators) * 25, 90),
                'method': 'text_recognition',
                'indicators': found_indicators
            }
        
        return {
            'detected': False,
            'confidence': 0
        }
    
    async def check_all_requirements(self, text: str, ui_analysis: Dict, image: Image.Image) -> Dict:
        """Tüm gereksinimleri kontrol et"""
        results = {}
        
        # Abone olma kontrolü
        if self.config.get('SUBSCRIBE_REQUIRED', True):
            subscribe_element = ui_analysis.get('elements', {}).get('subscribe_button', {})
            results['subscription'] = {
                'required': True,
                'status': subscribe_element.get('status', 'unknown'),
                'confidence': subscribe_element.get('confidence', 0),
                'satisfied': subscribe_element.get('status') == 'subscribed'
            }
        else:
            results['subscription'] = {'required': False, 'satisfied': True, 'confidence': 100}
        
        # Beğeni kontrolü
        if self.config.get('LIKE_REQUIRED', True):
            like_element = ui_analysis.get('elements', {}).get('like_button', {})
            results['like'] = {
                'required': True,
                'status': like_element.get('status', 'unknown'),
                'confidence': like_element.get('confidence', 0),
                'satisfied': like_element.get('status') == 'liked'
            }
        else:
            results['like'] = {'required': False, 'satisfied': True, 'confidence': 100}
        
        # Yorum kontrolü
        if self.config.get('COMMENT_REQUIRED', False):
            comment_element = ui_analysis.get('elements', {}).get('comment_section', {})
            # Yorum için daha esnek kontrol
            results['comment'] = {
                'required': True,
                'status': 'visible' if comment_element.get('detected') else 'not_visible',
                'confidence': comment_element.get('confidence', 0),
                'satisfied': comment_element.get('detected', False)
            }
        else:
            results['comment'] = {'required': False, 'satisfied': True, 'confidence': 100}
        
        return results
    
    def assess_image_quality(self, image: Image.Image) -> Dict:
        """Resim kalitesini değerlendir"""
        try:
            width, height = image.size
            total_pixels = width * height
            
            # Çözünürlük skoru
            resolution_score = 0
            if total_pixels >= 1920 * 1080:  # Full HD+
                resolution_score = 100
            elif total_pixels >= 1280 * 720:  # HD
                resolution_score = 80
            elif total_pixels >= 800 * 600:  # Minimum
                resolution_score = 60
            else:
                resolution_score = 30
            
            # Aspect ratio kontrolü
            aspect_ratio = width / height
            aspect_score = 100
            
            # Normal ekran oranları: 16:9, 16:10, 4:3
            normal_ratios = [16/9, 16/10, 4/3, 3/2]
            if not any(abs(aspect_ratio - ratio) < 0.1 for ratio in normal_ratios):
                aspect_score = 70  # Unusual aspect ratio
            
            # Genel kalite skoru
            quality_score = (resolution_score + aspect_score) / 2
            
            return {
                'resolution_score': resolution_score,
                'aspect_score': aspect_score,
                'quality_score': quality_score,
                'width': width,
                'height': height,
                'aspect_ratio': round(aspect_ratio, 2)
            }
            
        except Exception as e:
            return {
                'resolution_score': 0,
                'aspect_score': 0,
                'quality_score': 0,
                'error': str(e)
            }
    
    def calculate_final_score(self, analysis_data: Dict) -> Dict:
        """Final doğrulama skorunu hesapla"""
        try:
            scores = []
            errors = []
            details = {}
            
            # Platform kontrolü (5%)
            platform_check = analysis_data.get('platform_check', {})
            if platform_check.get('is_youtube', False):
                scores.append(platform_check.get('confidence', 0) * 0.05)
                details['platform'] = '✅ YouTube platform tespit edildi'
            else:
                errors.append('YouTube platformu tespit edilemedi')
                details['platform'] = '❌ YouTube platformu tespit edilemedi'
            
            # Kanal kontrolü (40% - EN ÖNEMLİ)
            channel_check = analysis_data.get('channel_check', {})
            if channel_check.get('is_correct_channel', False):
                scores.append(channel_check.get('confidence', 0) * 0.4)
                details['channel'] = f"✅ Doğru kanal: {channel_check.get('detected_channel')}"
            else:
                errors.append(f"Yanlış kanal: {channel_check.get('detected_channel', 'Bilinmeyen')}")
                details['channel'] = f"❌ Yanlış kanal: {channel_check.get('detected_channel', 'Bilinmeyen')}"
            
            # UI analizi (15%)
            ui_analysis = analysis_data.get('ui_analysis', {})
            if ui_analysis.get('is_valid_youtube_ui', False):
                scores.append(ui_analysis.get('ui_confidence', 0) * 0.15)
                details['ui'] = f"✅ YouTube UI tespit edildi ({ui_analysis.get('detected_elements', 0)}/6 element)"
            else:
                errors.append('Geçersiz YouTube UI')
                details['ui'] = '❌ Geçersiz YouTube UI'
            
            # Gereksinim kontrolleri (35%)
            requirements_check = analysis_data.get('requirements_check', {})
            requirement_scores = []
            
            for req_name, req_data in requirements_check.items():
                if req_data.get('required', False):
                    if req_data.get('satisfied', False):
                        requirement_scores.append(req_data.get('confidence', 0))
                        details[f'{req_name}_status'] = f"✅ {req_name.title()} gereksinimi karşılandı"
                    else:
                        errors.append(f"{req_name.title()} gereksinimi karşılanmadı")
                        details[f'{req_name}_status'] = f"❌ {req_name.title()} gereksinimi karşılanmadı"
                else:
                    requirement_scores.append(100)  # Gerekli değilse tam puan
            
            if requirement_scores:
                avg_req_score = sum(requirement_scores) / len(requirement_scores)
                scores.append(avg_req_score * 0.35)
            
            # Resim kalitesi (5%)
            image_quality = analysis_data.get('image_quality', {})
            quality_score = image_quality.get('quality_score', 0)
            scores.append(quality_score * 0.05)
            details['image_quality'] = f"📷 Resim kalitesi: {quality_score:.0f}%"
            
            # Final skor hesaplama
            final_confidence = sum(scores) if scores else 0
            final_confidence = max(0, min(100, final_confidence))  # 0-100 arası sınırla
            
            # Minimum güven kontrolü
            min_confidence = self.config.get('MIN_CONFIDENCE', 75)
            is_valid = (
                final_confidence >= min_confidence and
                len(errors) == 0 and
                channel_check.get('is_correct_channel', False)  # Kanal kontrolü mutlaka geçmeli
            )
            
            return {
                'is_valid': is_valid,
                'confidence': int(final_confidence),
                'errors': errors,
                'details': details,
                'min_confidence_required': min_confidence,
                'breakdown': {
                    'platform': platform_check.get('confidence', 0) * 0.05,
                    'channel': channel_check.get('confidence', 0) * 0.4,
                    'ui': ui_analysis.get('ui_confidence', 0) * 0.15,
                    'requirements': avg_req_score * 0.35 if 'avg_req_score' in locals() else 0,
                    'image_quality': quality_score * 0.05
                }
            }
            
        except Exception as e:
            self.logger.error(f"Final skor hesaplama hatası: {str(e)}")
            return {
                'is_valid': False,
                'confidence': 0,
                'errors': [f"Skor hesaplama hatası: {str(e)}"],
                'details': {},
                'breakdown': {}
            }
    
    def generate_detailed_report(self, result: Dict) -> str:
        """Detaylı doğrulama raporu oluştur"""
        if result.get('errors'):
            report = "❌ **Doğrulama Başarısız**\n\n"
            
            for error in result['errors'][:3]:  # İlk 3 hata
                report += f"• {error}\n"
            
            report += f"\n📊 **Güven Skoru:** {result.get('confidence', 0)}%\n"
            report += f"✅ **Gerekli Minimum:** {result.get('min_confidence_required', 75)}%\n"
            
        else:
            report = "✅ **Doğrulama Başarılı**\n\n"
            report += f"📊 **Güven Skoru:** {result.get('confidence', 0)}%\n"
        
        # Detayları ekle
        details = result.get('details', {})
        if details:
            report += "\n🔍 **Analiz Detayları:**\n"
            for key, value in details.items():
                report += f"{value}\n"
        
        return report