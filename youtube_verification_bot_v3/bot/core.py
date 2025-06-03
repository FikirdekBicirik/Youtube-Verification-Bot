# bot/core.py
import discord
from discord.ext import commands, tasks
import asyncio
from datetime import datetime, timedelta
import traceback
from typing import Dict, Optional, List
import json

from utils.logger import Logger
from utils.config import Config
from .database import Database
from .verification import AdvancedYouTubeVerification
from .image_memory import ImageMemory
from .security import SecurityManager

class YouTubeBot:
    """Ana YouTube Doğrulama Botu"""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger()
        self.database = Database()
        self.verifier = AdvancedYouTubeVerification(config)
        self.image_memory = ImageMemory()
        self.security = SecurityManager(config)
        
        # Bot ayarları
        intents = discord.Intents.default()
        intents.message_content = True
        intents.members = True
        intents.reactions = True
        intents.guilds = True
        
        self.bot = commands.Bot(
            command_prefix=config.get('COMMAND_PREFIX', '!'),
            intents=intents,
            help_command=None
        )
        
        self.setup_events()
        self.setup_commands()
        self.running = False
        
    def setup_events(self):
        """Bot olaylarını ayarla"""
        
        @self.bot.event
        async def on_ready():
            self.logger.system_event(f"Bot başlatıldı: {self.bot.user}")
            print(f"✅ {self.bot.user} olarak giriş yapıldı!")
            
            # Bot durumunu ayarla
            await self.bot.change_presence(
                activity=discord.Activity(
                    type=discord.ActivityType.watching,
                    name="YouTube doğrulamaları 👀"
                ),
                status=discord.Status.online
            )
            
            # Periyodik görevleri başlat
            if not self.daily_tasks.is_running():
                self.daily_tasks.start()
            
            if not self.security_check.is_running():
                self.security_check.start()
                
            # Eski mesajları analiz et
            await self.analyze_existing_images()
            
            self.running = True
        
        @self.bot.event
        async def on_message(message):
            # Bot'un kendi mesajlarını yoksay
            if message.author.bot:
                return
            
            # Doğrulama kanalı kontrolü
            if message.channel.id == self.config.get('VERIFICATION_CHANNEL_ID'):
                await self.handle_verification_submission(message)
            
            await self.bot.process_commands(message)
        
        @self.bot.event
        async def on_reaction_add(reaction, user):
            """Admin onayları için reaction'ları dinle"""
            await self.handle_admin_reaction(reaction, user)
        
        @self.bot.event
        async def on_member_remove(member):
            """Üye ayrıldığında veritabanından sil"""
            if self.database.is_user_verified(member.id):
                self.database.remove_verified_user(member.id)
                self.logger.info(f"Ayrılan üye veritabanından silindi: {member.display_name}", user_id=member.id)
        
        @self.bot.event
        async def on_member_update(before, after):
            """Üye rolleri değiştiğinde kontrol et"""
            subscriber_role_id = self.config.get('SUBSCRIBER_ROLE_ID')
            
            # Abone rolü kaldırıldı mı?
            if subscriber_role_id:
                before_has_role = any(role.id == subscriber_role_id for role in before.roles)
                after_has_role = any(role.id == subscriber_role_id for role in after.roles)
                
                if before_has_role and not after_has_role:
                    # Rol kaldırıldı, veritabanından da kaldır
                    if self.database.is_user_verified(after.id):
                        self.database.remove_verified_user(after.id)
                        self.logger.security(
                            f"Abone rolü kaldırılan kullanıcı veritabanından silindi: {after.display_name}",
                            user_id=after.id
                        )
        
        @self.bot.event
        async def on_command_error(ctx, error):
            """Komut hatalarını yakala"""
            if isinstance(error, commands.CommandNotFound):
                return
            elif isinstance(error, commands.MissingPermissions):
                await ctx.send("❌ Bu komutu kullanmak için yetkiniz yok!")
            elif isinstance(error, commands.MissingRole):
                await ctx.send("❌ Bu komutu kullanmak için gerekli role sahip değilsiniz!")
            else:
                self.logger.error(f"Komut hatası: {str(error)}", user_id=ctx.author.id)
                await ctx.send("❌ Bir hata oluştu!")
    
    def setup_commands(self):
        """Bot komutlarını ayarla"""
        
        @self.bot.command(name='stats', aliases=['istatistik'])
        async def stats_command(ctx):
            """Bot istatistikleri"""
            if not await self.check_admin_permission(ctx):
                return
            
            stats = self.database.get_statistics()
            
            embed = discord.Embed(
                title="📊 Bot İstatistikleri",
                color=0x00ff00,
                timestamp=datetime.now()
            )
            
            embed.add_field(
                name="👥 Doğrulanmış Kullanıcılar",
                value=f"```\nToplam: {stats.get('total_verified', 0)}\nBugün: {stats.get('today_verified', 0)}```",
                inline=True
            )
            
            embed.add_field(
                name="📋 Bekleyen İstekler",
                value=f"```\nToplam: {stats.get('pending_requests', 0)}\nBugün: {stats.get('today_pending', 0)}```",
                inline=True
            )
            
            embed.add_field(
                name="❌ Reddedilen",
                value=f"```\nToplam: {stats.get('rejected', 0)}\nBugün: {stats.get('today_rejected', 0)}```",
                inline=True
            )
            
            embed.add_field(
                name="🛡️ Güvenlik",
                value=f"```\nDuplicate: {stats.get('duplicates_blocked', 0)}\nSpam: {stats.get('spam_blocked', 0)}```",
                inline=True
            )
            
            embed.add_field(
                name="⚡ Sistem",
                value=f"```\nUptime: {self.get_uptime()}\nMemory: {stats.get('memory_usage', 0)} MB```",
                inline=True
            )
            
            embed.add_field(
                name="🎯 Başarı Oranı",
                value=f"```\n{stats.get('success_rate', 0)}%```",
                inline=True
            )
            
            await ctx.send(embed=embed)
        
        @self.bot.command(name='user', aliases=['kullanici'])
        async def user_command(ctx, member: discord.Member = None):
            """Kullanıcı bilgileri"""
            if not await self.check_admin_permission(ctx):
                return
            
            if not member:
                member = ctx.author
            
            user_data = self.database.get_user_data(member.id)
            
            embed = discord.Embed(
                title=f"👤 {member.display_name}",
                color=0x00ff00 if user_data.get('is_verified') else 0xff0000,
                timestamp=datetime.now()
            )
            
            embed.set_thumbnail(url=member.avatar.url if member.avatar else member.default_avatar.url)
            
            embed.add_field(
                name="✅ Doğrulama Durumu",
                value="Doğrulanmış" if user_data.get('is_verified') else "Doğrulanmamış",
                inline=True
            )
            
            embed.add_field(
                name="📊 Deneme Sayısı",
                value=user_data.get('attempts', 0),
                inline=True
            )
            
            if user_data.get('last_verification'):
                embed.add_field(
                    name="📅 Son Doğrulama",
                    value=f"<t:{int(datetime.fromisoformat(user_data['last_verification']).timestamp())}:R>",
                    inline=True
                )
            
            embed.add_field(
                name="🔒 Güvenlik Skoru",
                value=f"{user_data.get('security_score', 100)}/100",
                inline=True
            )
            
            await ctx.send(embed=embed)
        
        @self.bot.command(name='verify', aliases=['dogrula'])
        async def manual_verify(ctx, member: discord.Member):
            """Manuel doğrulama (Admin)"""
            if not await self.check_admin_permission(ctx):
                return
            
            subscriber_role = ctx.guild.get_role(self.config.get('SUBSCRIBER_ROLE_ID'))
            if not subscriber_role:
                await ctx.send("❌ Abone rolü bulunamadı!")
                return
            
            # Zaten doğrulanmış mı?
            if self.database.is_user_verified(member.id):
                await ctx.send(f"⚠️ {member.display_name} zaten doğrulanmış!")
                return
            
            # Rolü ver
            await member.add_roles(subscriber_role, reason=f"Manuel doğrulama - {ctx.author.display_name}")
            
            # Veritabanına kaydet
            self.database.add_verified_user(member.id, member.display_name, manual=True)
            
            # Log
            self.logger.admin_action(
                ctx.author.id, ctx.author.display_name,
                "manuel_dogrulama", member.display_name
            )
            
            embed = discord.Embed(
                title="✅ Manuel Doğrulama",
                description=f"{member.mention} başarıyla doğrulandı!",
                color=0x00ff00
            )
            
            await ctx.send(embed=embed)
        
        @self.bot.command(name='unverify', aliases=['dogrulamakaldir'])
        async def unverify_command(ctx, member: discord.Member):
            """Doğrulamayı kaldır (Admin)"""
            if not await self.check_admin_permission(ctx):
                return
            
            if not self.database.is_user_verified(member.id):
                await ctx.send(f"⚠️ {member.display_name} zaten doğrulanmamış!")
                return
            
            # Rolü kaldır
            subscriber_role = ctx.guild.get_role(self.config.get('SUBSCRIBER_ROLE_ID'))
            if subscriber_role and subscriber_role in member.roles:
                await member.remove_roles(subscriber_role, reason=f"Doğrulama kaldırıldı - {ctx.author.display_name}")
            
            # Veritabanından kaldır
            self.database.remove_verified_user(member.id)
            
            # Log
            self.logger.admin_action(
                ctx.author.id, ctx.author.display_name,
                "dogrulama_kaldir", member.display_name
            )
            
            embed = discord.Embed(
                title="❌ Doğrulama Kaldırıldı",
                description=f"{member.mention} doğrulaması kaldırıldı!",
                color=0xff0000
            )
            
            await ctx.send(embed=embed)
        
        @self.bot.command(name='cleanup', aliases=['temizle'])
        async def cleanup_command(ctx, limit: int = 10):
            """Doğrulama kanalını temizle"""
            if not await self.check_admin_permission(ctx):
                return
            
            if ctx.channel.id != self.config.get('VERIFICATION_CHANNEL_ID'):
                await ctx.send("❌ Bu komut sadece doğrulama kanalında kullanılabilir!")
                return
            
            deleted = await ctx.channel.purge(limit=limit + 1)
            
            temp_msg = await ctx.send(f"🧹 {len(deleted)-1} mesaj temizlendi!")
            await asyncio.sleep(3)
            await temp_msg.delete()
        
        @self.bot.command(name='help', aliases=['yardim'])
        async def help_command(ctx):
            """Yardım menüsü"""
            is_admin = await self.check_admin_permission(ctx, silent=True)
            
            embed = discord.Embed(
                title="🤖 YouTube Doğrulama Botu",
                description="Kanal doğrulama sistemi",
                color=0x00ff00
            )
            
            if is_admin:
                embed.add_field(
                    name="👑 Admin Komutları",
                    value="""
`!stats` - Bot istatistikleri
`!user [@kullanıcı]` - Kullanıcı bilgileri
`!verify @kullanıcı` - Manuel doğrulama
`!unverify @kullanıcı` - Doğrulamayı kaldır
`!cleanup [sayı]` - Kanal temizle
                    """,
                    inline=False
                )
            
            embed.add_field(
                name="📋 Doğrulama Süreci",
                value=f"""
1️⃣ **{self.config.get('YOUR_CHANNEL_NAME')}** kanalına abone ol
2️⃣ Son videoyu beğen
3️⃣ Yorum yap
4️⃣ Ekran görüntüsü al
5️⃣ <#{self.config.get('VERIFICATION_CHANNEL_ID')}> kanalına yükle
                """,
                inline=False
            )
            
            embed.add_field(
                name="ℹ️ Önemli Notlar",
                value="""
• Sadece PNG, JPG, JPEG formatları kabul edilir
• Ekran görüntüsü en az 800x600 olmalı
• Spam yapmayın, sadece bir kez gönderin
• Yanlış kanal ekran görüntüleri reddedilir
                """,
                inline=False
            )
            
            await ctx.send(embed=embed)
    
    async def handle_verification_submission(self, message):
        """Doğrulama kanalına gelen mesajları işle"""
        try:
            # Rate limiting kontrolü
            if self.security.is_rate_limited(message.author.id):
                await message.reply(
                    "⏰ **Çok hızlı deneme yapıyorsunuz!**\n"
                    "5 dakika bekleyin ve tekrar deneyin.",
                    delete_after=10
                )
                await asyncio.sleep(10)
                await self.safe_delete(message)
                return
            
            # Resim kontrolü
            if not message.attachments:
                await message.reply(
                    "❌ **Ekran görüntünüz nerede?**\n"
                    f"📺 **{self.config.get('YOUR_CHANNEL_NAME')}** kanalından ekran görüntüsü yükleyin!\n\n"
                    "📋 **Gerekli işlemler:**\n"
                    "✅ Kanala abone ol\n"
                    "👍 Videoyu beğen\n"
                    "💬 Yorum yap",
                    delete_after=15
                )
                await asyncio.sleep(15)
                await self.safe_delete(message)
                return
            
            attachment = message.attachments[0]
            
            # Dosya doğrulaması
            if not self.security.validate_file(attachment):
                await message.reply(
                    "❌ **Geçersiz dosya!**\n"
                    "📁 **Desteklenen formatlar:** PNG, JPG, JPEG, GIF, WEBP\n"
                    "📏 **Maksimum boyut:** 15MB",
                    delete_after=10
                )
                await asyncio.sleep(10)
                await self.safe_delete(message)
                return
            
            # Zaten doğrulanmış mı?
            if self.database.is_user_verified(message.author.id):
                # Ama rolü yok mu? (Rol kaldırılmışsa)
                subscriber_role = message.guild.get_role(self.config.get('SUBSCRIBER_ROLE_ID'))
                if subscriber_role and subscriber_role not in message.author.roles:
                    # Veritabanından kaldır ve yeni doğrulama yap
                    self.database.remove_verified_user(message.author.id)
                    self.logger.info(f"Rolü olmayan doğrulanmış kullanıcı tespit edildi, yeniden doğrulama: {message.author.display_name}", user_id=message.author.id)
                else:
                    await message.reply(
                        "✅ **Zaten doğrulanmış bir kullanıcısınız!**\n"
                        "🎉 Kanalımızı desteklediğiniz için teşekkürler!",
                        delete_after=10
                    )
                    return
            
            # Duplicate image kontrolü
            if self.config.get('DUPLICATE_CHECK'):
                duplicate_info = await self.image_memory.check_duplicate(attachment.url)
                if duplicate_info:
                    await message.reply(
                        "🚫 **Bu resim daha önce kullanılmış!**\n"
                        f"👤 **İlk kullanan:** {duplicate_info['username']}\n"
                        f"📅 **Tarih:** <t:{duplicate_info['timestamp']}:R>\n\n"
                        "⚠️ **Çalıntı resim kullanmayın!** Kendi ekran görüntünüzü alın.",
                        delete_after=20
                    )
                    
                    # Güvenlik logu
                    self.logger.security(
                        f"Duplicate resim tespit edildi: {message.author.display_name}",
                        extra_data=duplicate_info,
                        user_id=message.author.id
                    )
                    
                    await asyncio.sleep(20)
                    await self.safe_delete(message)
                    return
            
            # İşlem mesajı
            loading_msg = await message.reply(
                "⏳ **Ekran görüntünüz analiz ediliyor...**\n"
                "🔍 Kanal kontrolü, OCR analizi ve güvenlik kontrolleri yapılıyor.\n"
                "📊 Bu işlem 10-30 saniye sürebilir, lütfen bekleyin..."
            )
            
            # Veritabanına pending olarak ekle
            self.database.add_pending_verification(
                message.author.id,
                message.id,
                attachment.url,
                message.author.display_name
            )
            
            # Resmi hafızaya kaydet
            await self.image_memory.store_image(
                attachment.url,
                message.author.id,
                message.author.display_name,
                message.id
            )
            
            # Doğrulama işlemi
            await self.process_verification(message, attachment.url, loading_msg)
            
        except Exception as e:
            self.logger.error(f"Doğrulama işleme hatası: {str(e)}", user_id=message.author.id)
            try:
                await message.reply(
                    "❌ **Beklenmeyen bir hata oluştu!**\n"
                    "🔄 Lütfen tekrar deneyin veya yöneticilerle iletişime geçin."
                )
            except:
                pass
    
    async def process_verification(self, message, image_url, loading_msg):
        """Doğrulama işlemini gerçekleştir"""
        try:
            # Gelişmiş doğrulama
            is_valid, analysis_result = await self.verifier.verify_screenshot(image_url, message.author.id)
            
            confidence = analysis_result.get('confidence', 0)
            
            # Karar verme
            if analysis_result.get('error') == 'wrong_channel':
                await self.reject_wrong_channel(message, analysis_result, loading_msg)
            elif analysis_result.get('errors'):
                await self.reject_missing_requirements(message, analysis_result, loading_msg)
            elif confidence >= self.config.get('AUTO_APPROVE_THRESHOLD', 80):
                await self.approve_verification(message, analysis_result, loading_msg, auto=True)
            elif confidence >= self.config.get('MANUAL_REVIEW_THRESHOLD', 40):
                await self.send_for_manual_review(message, analysis_result, loading_msg)
            else:
                await self.reject_verification(message, analysis_result, loading_msg, auto=True)
            
        except Exception as e:
            self.logger.error(f"Doğrulama işlemi hatası: {str(e)}", user_id=message.author.id)
            await loading_msg.edit(
                content="❌ **Doğrulama sırasında hata oluştu.**\n"
                       "🔄 Lütfen tekrar deneyin."
            )
    
    async def reject_wrong_channel(self, message, analysis_result, loading_msg):
        """Yanlış kanal reddini işle"""
        detected_channel = analysis_result.get('detected_channel', 'Bilinmeyen')
        expected_channel = self.config.get('YOUR_CHANNEL_NAME')
        
        embed = discord.Embed(
            title="❌ Yanlış Kanal Tespit Edildi!",
            description=f"Bu ekran görüntüsü **{expected_channel}** kanalından değil!",
            color=0xff0000,
            timestamp=datetime.now()
        )
        
        embed.add_field(
            name="🔍 Tespit Edilen Kanal",
            value=f"`{detected_channel}`",
            inline=True
        )
        
        embed.add_field(
            name="✅ Doğru Kanal",
            value=f"`{expected_channel}`",
            inline=True
        )
        
        embed.add_field(
            name="📋 Yapmanız Gerekenler",
            value=f"""
1️⃣ **{expected_channel}** kanalına gidin
2️⃣ Kanala abone olun
3️⃣ Son videoyu beğenin
4️⃣ Yorum yapın
5️⃣ Ekran görüntüsü alıp tekrar gönderin
            """,
            inline=False
        )
        
        # Veritabanını güncelle
        self.database.update_verification_status(message.id, 'rejected_wrong_channel')
        
        # Log
        self.logger.verification_attempt(
            message.author.id, message.author.display_name,
            'rejected_wrong_channel', analysis_result.get('confidence', 0),
            {'detected_channel': detected_channel, 'expected_channel': expected_channel}
        )
        
        await loading_msg.edit(content=None, embed=embed)
    
    async def reject_missing_requirements(self, message, analysis_result, loading_msg):
        """Eksik gereksinimler reddini işle"""
        errors = analysis_result.get('errors', [])
        
        embed = discord.Embed(
            title="❌ Eksik İşlemler Tespit Edildi!",
            description="Lütfen aşağıdaki eksik işlemleri tamamlayın:",
            color=0xffa500,
            timestamp=datetime.now()
        )
        
        # Eksik işlemleri listele
        missing_requirements = []
        for error in errors:
            if 'abone' in error.lower() or 'subscrib' in error.lower():
                missing_requirements.append("🔔 **Kanala abone ol**")
            elif 'beğen' in error.lower() or 'like' in error.lower():
                missing_requirements.append("👍 **Videoyu beğen**")
            elif 'yorum' in error.lower() or 'comment' in error.lower():
                missing_requirements.append("💬 **Yorum yap**")
        
        if missing_requirements:
            embed.add_field(
                name="📋 Eksik İşlemler",
                value="\n".join(missing_requirements),
                inline=False
            )
        
        embed.add_field(
            name="🎯 Güven Skoru",
            value=f"{analysis_result.get('confidence', 0)}%",
            inline=True
        )
        
        embed.add_field(
            name="✅ Gerekli Minimum",
            value=f"{self.config.get('MIN_CONFIDENCE', 75)}%",
            inline=True
        )
        
        embed.add_field(
            name="🔄 Sonraki Adım",
            value="Eksik işlemleri tamamlayıp yeni ekran görüntüsü gönderin",
            inline=False
        )
        
        # Veritabanını güncelle
        self.database.update_verification_status(message.id, 'rejected_missing_requirements')
        
        # Log
        self.logger.verification_attempt(
            message.author.id, message.author.display_name,
            'rejected_missing_requirements', analysis_result.get('confidence', 0),
            {'errors': errors}
        )
        
        await loading_msg.edit(content=None, embed=embed)
    
    async def approve_verification(self, message, analysis_result, loading_msg, auto=False, admin_user=None):
        """Doğrulamayı onayla ve rol ver"""
        try:
            guild = message.guild
            member = message.author
            subscriber_role = guild.get_role(self.config.get('SUBSCRIBER_ROLE_ID'))
            
            if not subscriber_role:
                await loading_msg.edit(content="❌ Abone rolü bulunamadı! Lütfen yöneticilerle iletişime geçin.")
                return
            
            # Rolü ver
            await member.add_roles(subscriber_role, reason="YouTube doğrulama onaylandı")
            
            # Veritabanına kaydet
            self.database.add_verified_user(member.id, member.display_name)
            self.database.update_verification_status(message.id, 'approved', admin_user.id if admin_user else None)
            
            # Başarı embed'i
            embed = discord.Embed(
                title="🎉 Doğrulama Başarılı!",
                description=f"**{self.config.get('YOUR_CHANNEL_NAME')}** kanalımıza verdiğiniz destek için teşekkürler!",
                color=0x00ff00,
                timestamp=datetime.now()
            )
            
            embed.set_author(
                name=member.display_name,
                icon_url=member.avatar.url if member.avatar else member.default_avatar.url
            )
            
            embed.add_field(
                name="🎁 Verilen Rol",
                value=subscriber_role.mention,
                inline=True
            )
            
            embed.add_field(
                name="📊 Güven Skoru",
                value=f"{analysis_result.get('confidence', 0)}%",
                inline=True
            )
            
            approval_type = "🤖 Otomatik" if auto else f"👤 Manuel ({admin_user.display_name})"
            embed.add_field(
                name="✅ Onay Türü",
                value=approval_type,
                inline=True
            )
            
            embed.set_footer(text="Kanalımızı desteklediğiniz için teşekkürler! 🙏")
            
            await loading_msg.edit(content=None, embed=embed)
            
            # DM gönder
            if self.config.get('DM_NOTIFICATIONS'):
                try:
                    dm_embed = discord.Embed(
                        title="🎉 Doğrulama Onaylandı!",
                        description=f"**{guild.name}** sunucusunda YouTube doğrulamanız onaylandı!",
                        color=0x00ff00
                    )
                    await member.send(embed=dm_embed)
                except:
                    pass  # DM gönderilemezse sessiz geç
            
            # Log
            self.logger.verification_attempt(
                member.id, member.display_name, 'approved',
                analysis_result.get('confidence', 0),
                {'auto': auto, 'admin': admin_user.display_name if admin_user else None}
            )
            
            # Admin kanalına bildir
            await self.send_admin_notification(
                f"✅ **Doğrulama Onaylandı**\n"
                f"👤 {member.mention} ({member.display_name})\n"
                f"📊 Güven: {analysis_result.get('confidence', 0)}%\n"
                f"🔄 Tür: {approval_type}"
            )
            
        except Exception as e:
            self.logger.error(f"Onaylama hatası: {str(e)}", user_id=message.author.id)
            await loading_msg.edit(content="❌ Rol verme hatası oluştu! Lütfen yöneticilerle iletişime geçin.")
    
    async def send_for_manual_review(self, message, analysis_result, loading_msg):
        """Manuel inceleme için gönder"""
        try:
            log_channel = self.bot.get_channel(self.config.get('LOG_CHANNEL_ID'))
            
            if not log_channel:
                # Log kanalı yoksa otomatik karar ver
                confidence = analysis_result.get('confidence', 0)
                if confidence >= 60:
                    await self.approve_verification(message, analysis_result, loading_msg, auto=True)
                else:
                    await self.reject_verification(message, analysis_result, loading_msg, auto=True)
                return
            
            # Admin paneli embed'i
            embed = discord.Embed(
                title="🔍 Manuel İnceleme Gerekli",
                color=0xffa500,
                timestamp=datetime.now()
            )
            
            embed.set_author(
                name=message.author.display_name,
                icon_url=message.author.avatar.url if message.author.avatar else message.author.default_avatar.url
            )
            
            embed.add_field(
                name="👤 Kullanıcı",
                value=f"{message.author.mention}\n`{message.author.display_name}`",
                inline=True
            )
            
            embed.add_field(
                name="📊 AI Güven Skoru",
                value=f"{analysis_result.get('confidence', 0)}%",
                inline=True
            )
            
            embed.add_field(
                name="📅 Tarih",
                value=f"<t:{int(message.created_at.timestamp())}:R>",
                inline=True
            )
            
            # Analiz detayları
            details = analysis_result.get('details', {})
            detail_text = ""
            for key, value in details.items():
                if isinstance(value, str):
                    detail_text += f"{key}: {value}\n"
            
            if detail_text:
                embed.add_field(
                    name="🔍 Analiz Detayları",
                    value=f"```\n{detail_text[:1000]}```",
                    inline=False
                )
            
            embed.add_field(
                name="🔗 Mesaj",
                value=f"[Mesaja Git](https://discord.com/channels/{message.guild.id}/{message.channel.id}/{message.id})",
                inline=False
            )
            
            # Ekran görüntüsü
            if message.attachments:
                embed.set_image(url=message.attachments[0].url)
            
            embed.set_footer(text=f"Mesaj ID: {message.id}")
            
            # Admin mesajını gönder
            admin_msg = await log_channel.send(embed=embed)
            
            # Reaction'ları ekle
            await admin_msg.add_reaction('✅')
            await admin_msg.add_reaction('❌')
            await admin_msg.add_reaction('🔄')  # Yeniden analiz
            
            # Kullanıcıya bilgi ver
            user_embed = discord.Embed(
                title="⏳ Manuel İnceleme",
                description="Ekran görüntünüz manuel incelemeye alındı.",
                color=0xffa500
            )
            
            user_embed.add_field(
                name="⏱️ Bekleme Süresi",
                value="Genellikle 1-24 saat içinde",
                inline=True
            )
            
            user_embed.add_field(
                name="📊 Güven Skoru",
                value=f"{analysis_result.get('confidence', 0)}%",
                inline=True
            )
            
            user_embed.add_field(
                name="📋 Kontrol Edilen",
                value="✅ Kanal doğruluğu\n👍 Beğeni durumu\n🔔 Abone durumu",
                inline=False
            )
            
            await loading_msg.edit(content=None, embed=user_embed)
            
            # Log
            self.logger.verification_attempt(
                message.author.id, message.author.display_name,
                'manual_review', analysis_result.get('confidence', 0)
            )
            
        except Exception as e:
            self.logger.error(f"Manuel inceleme gönderme hatası: {str(e)}", user_id=message.author.id)
    
    async def handle_admin_reaction(self, reaction, user):
        """Admin reaction'larını işle"""
        if user.bot:
            return
        
        # Log kanalında mı?
        if reaction.message.channel.id != self.config.get('LOG_CHANNEL_ID'):
            return
        
        # Admin yetkisi var mı?
        if not await self.check_admin_permission_user(user):
            await reaction.remove(user)
            return
        
        # Doğru reaction mı?
        if str(reaction.emoji) not in ['✅', '❌', '🔄']:
            return
        
        try:
            # Embed'den mesaj ID'sini al
            embed = reaction.message.embeds[0] if reaction.message.embeds else None
            if not embed or not embed.footer:
                return
            
            footer_text = embed.footer.text
            if not footer_text.startswith("Mesaj ID: "):
                return
            
            message_id = int(footer_text.replace("Mesaj ID: ", ""))
            
            # Orijinal mesajı bul
            verification_channel = self.bot.get_channel(self.config.get('VERIFICATION_CHANNEL_ID'))
            original_message = await verification_channel.fetch_message(message_id)
            
            if str(reaction.emoji) == '✅':
                # Manuel onay
                await self.approve_verification_from_admin(original_message, user)
            elif str(reaction.emoji) == '❌':
                # Manuel red
                await self.reject_verification_from_admin(original_message, user)
            elif str(reaction.emoji) == '🔄':
                # Yeniden analiz
                await self.reanalyze_verification(original_message, user)
            
            # Admin mesajını güncelle
            await self.update_admin_message(reaction.message, original_message, str(reaction.emoji), user)
            
        except Exception as e:
            self.logger.error(f"Admin reaction işleme hatası: {str(e)}")
    
    async def approve_verification_from_admin(self, message, admin_user):
        """Admin tarafından manuel onay"""
        analysis_result = {'confidence': 100}  # Manuel onay için 100% güven
        await self.approve_verification(message, analysis_result, None, admin_user=admin_user)
    
    async def reject_verification_from_admin(self, message, admin_user):
        """Admin tarafından manuel red"""
        analysis_result = {'confidence': 0}
        await self.reject_verification(message, analysis_result, None, admin_user=admin_user)
    
    async def reject_verification(self, message, analysis_result, loading_msg, auto=False, admin_user=None):
        """Doğrulamayı reddet"""
        try:
            # Veritabanını güncelle
            self.database.update_verification_status(message.id, 'rejected', admin_user.id if admin_user else None)
            
            # Red embed'i
            embed = discord.Embed(
                title="❌ Doğrulama Reddedildi",
                description="Maalesef doğrulamanız reddedildi.",
                color=0xff0000,
                timestamp=datetime.now()
            )
            
            confidence = analysis_result.get('confidence', 0)
            embed.add_field(
                name="📊 Güven Skoru",
                value=f"{confidence}%",
                inline=True
            )
            
            embed.add_field(
                name="✅ Gerekli Minimum",
                value=f"{self.config.get('MIN_CONFIDENCE', 75)}%",
                inline=True
            )
            
            # Hata detayları
            errors = analysis_result.get('errors', [])
            if errors:
                error_text = "\n".join([f"• {error}" for error in errors[:5]])
                embed.add_field(
                    name="🔍 Tespit Edilen Sorunlar",
                    value=error_text,
                    inline=False
                )
            
            embed.add_field(
                name="📋 Yapmanız Gerekenler",
                value=f"""
1️⃣ **{self.config.get('YOUR_CHANNEL_NAME')}** kanalına abone olun
2️⃣ Son videoyu beğenin
3️⃣ Yorum yapın
4️⃣ Tam ekran görüntüsü alın
5️⃣ Tekrar deneyin
                """,
                inline=False
            )
            
            if loading_msg:
                await loading_msg.edit(content=None, embed=embed)
            else:
                await message.reply(embed=embed)
            
            # Log
            rejection_type = "🤖 Otomatik" if auto else f"👤 Manuel ({admin_user.display_name if admin_user else 'Sistem'})"
            self.logger.verification_attempt(
                message.author.id, message.author.display_name,
                'rejected', confidence,
                {'auto': auto, 'admin': admin_user.display_name if admin_user else None, 'errors': errors}
            )
            
        except Exception as e:
            self.logger.error(f"Reddetme hatası: {str(e)}", user_id=message.author.id)
    
    # Yardımcı fonksiyonlar
    async def check_admin_permission(self, ctx, silent=False):
        """Admin yetkisi kontrolü"""
        admin_role_id = self.config.get('ADMIN_ROLE_ID')
        admin_role = discord.utils.get(ctx.author.roles, id=admin_role_id)
        
        if not admin_role:
            if not silent:
                await ctx.send("❌ Bu komutu kullanmak için admin yetkisi gerekli!")
            return False
        return True
    
    async def check_admin_permission_user(self, user):
        """Kullanıcı admin yetkisi kontrolü"""
        admin_role_id = self.config.get('ADMIN_ROLE_ID')
        return any(role.id == admin_role_id for role in user.roles)
    
    async def safe_delete(self, message):
        """Güvenli mesaj silme"""
        try:
            await message.delete()
        except:
            pass
    
    async def send_admin_notification(self, content):
        """Admin kanalına bildirim gönder"""
        try:
            log_channel = self.bot.get_channel(self.config.get('LOG_CHANNEL_ID'))
            if log_channel:
                await log_channel.send(content)
        except Exception as e:
            self.logger.error(f"Admin bildirimi hatası: {str(e)}")
    
    def get_uptime(self):
        """Bot uptime hesapla"""
        # Basit uptime hesaplaması
        return "Aktif"
    
    async def analyze_existing_images(self):
        """Mevcut resimleri analiz et"""
        try:
            verification_channel = self.bot.get_channel(self.config.get('VERIFICATION_CHANNEL_ID'))
            if not verification_channel:
                return
            
            self.logger.info("Mevcut resimler analiz ediliyor...")
            
            # Son 100 mesajı kontrol et
            async for message in verification_channel.history(limit=100):
                if message.attachments and not message.author.bot:
                    for attachment in message.attachments:
                        if self.security.validate_file(attachment):
                            await self.image_memory.store_image(
                                attachment.url,
                                message.author.id,
                                message.author.display_name,
                                message.id,
                                existing=True
                            )
            
            self.logger.info("Mevcut resim analizi tamamlandı")
            
        except Exception as e:
            self.logger.error(f"Mevcut resim analizi hatası: {str(e)}")
    
    # Periyodik görevler
    @tasks.loop(hours=24)
    async def daily_tasks(self):
        """Günlük görevler"""
        try:
            # İstatistikleri log kanalına gönder
            await self.send_daily_stats()
            
            # Eski logları temizle
            self.logger.cleanup_old_logs(30)
            
            # Eski geçici dosyaları temizle
            await self.cleanup_temp_files()
            
        except Exception as e:
            self.logger.error(f"Günlük görev hatası: {str(e)}")
    
    @tasks.loop(minutes=30)
    async def security_check(self):
        """Güvenlik kontrolleri"""
        try:
            # Rate limit temizliği
            self.security.cleanup_rate_limits()
            
            # Suspicious activity kontrolü
            await self.security.check_suspicious_activity()
            
        except Exception as e:
            self.logger.error(f"Güvenlik kontrolü hatası: {str(e)}")
    
    async def send_daily_stats(self):
        """Günlük istatistikleri gönder"""
        try:
            stats = self.database.get_statistics()
            log_channel = self.bot.get_channel(self.config.get('LOG_CHANNEL_ID'))
            
            if not log_channel:
                return
            
            embed = discord.Embed(
                title="📊 Günlük Rapor",
                color=0x00ff00,
                timestamp=datetime.now()
            )
            
            embed.add_field(
                name="✅ Doğrulanmış",
                value=f"Bugün: {stats.get('today_verified', 0)}\nToplam: {stats.get('total_verified', 0)}",
                inline=True
            )
            
            embed.add_field(
                name="❌ Reddedilen",
                value=f"Bugün: {stats.get('today_rejected', 0)}\nToplam: {stats.get('rejected', 0)}",
                inline=True
            )
            
            embed.add_field(
                name="🛡️ Güvenlik",
                value=f"Spam: {stats.get('spam_blocked', 0)}\nDuplicate: {stats.get('duplicates_blocked', 0)}",
                inline=True
            )
            
            await log_channel.send(embed=embed)
            
        except Exception as e:
            self.logger.error(f"Günlük rapor hatası: {str(e)}")
    
    async def cleanup_temp_files(self):
        """Geçici dosyaları temizle"""
        import os
        import glob
        
        try:
            temp_dir = "data/temp"
            if os.path.exists(temp_dir):
                files = glob.glob(os.path.join(temp_dir, "*"))
                for file in files:
                    if os.path.getctime(file) < (datetime.now() - timedelta(days=1)).timestamp():
                        os.remove(file)
        except Exception as e:
            self.logger.error(f"Temp dosya temizleme hatası: {str(e)}")
    
    async def start(self):
        """Botu başlat"""
        try:
            await self.bot.start(self.config.get('DISCORD_TOKEN'))
        except Exception as e:
            self.logger.error(f"Bot başlatma hatası: {str(e)}")
            raise
    
    async def stop(self):
        """Botu durdur"""
        if self.running:
            self.running = False
            await self.bot.close()
            self.logger.info("Bot durduruldu")