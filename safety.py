import os
import datetime
import logging
from logging.handlers import RotatingFileHandler

# Günlük ayarları
LOG_DIZINI = "logs"
LOG_DOSYASI = "uygulama.log"
LOG_SEVIYESI = logging.DEBUG
LOG_FORMATI = "%(asctime)s - %(levelname)s - %(message)s"

def setup_logging():
    if not os.path.exists(LOG_DIZINI):
        os.makedirs(LOG_DIZINI)
    
    log_dosyasi = os.path.join(LOG_DIZINI, LOG_DOSYASI)
    
    logging.basicConfig(level=LOG_SEVIYESI, format=LOG_FORMATI)
    
    rotating_handler = RotatingFileHandler(log_dosyasi, maxBytes=10*1024*1024, backupCount=5)
    rotating_handler.setFormatter(logging.Formatter(LOG_FORMATI))
    logging.getLogger().addHandler(rotating_handler)

def ana_program():
    kullanici_adi = input("Kullanıcı adınızı girin: ")
    islem = input("Yapmak istediğiniz işlemi girin: ")
    
    try:
        if islem == "para_transferi":
            alici = input("Alıcı kullanıcı adını girin: ")
            miktar = float(input("Transfer miktarını girin: "))
            # Para transferi işlemi burada gerçekleştirilir
            print(f"{kullanici_adi} tarafından {alici} kullanıcısına {miktar} TL transferi gerçekleştirildi.")
            logging.info(f"Kullanıcı: {kullanici_adi} - İşlem: Para Transferi - Alıcı: {alici} - Miktar: {miktar} TL")
        elif islem == "odeme":
            # Ödeme işlemi burada gerçekleştirilir
            print("Ödeme işlemi gerçekleştirildi.")
            logging.info(f"Kullanıcı: {kullanici_adi} - İşlem: Ödeme")
        elif islem == "diger":
            # Diğer işlem burada gerçekleştirilir
            print("Diğer işlem gerçekleştirildi.")
            logging.info(f"Kullanıcı: {kullanici_adi} - İşlem: Diğer")
        else:
            print("Geçersiz işlem seçeneği.")
            logging.warning(f"Kullanıcı: {kullanici_adi} - Geçersiz İşlem: {islem}")
    except Exception as e:
        print("İşlem sırasında bir hata oluştu.")
        logging.error(f"Kullanıcı: {kullanici_adi} - İşlem: {islem} - Hata: {str(e)}")
        
if __name__ == "__main__":
    setup_logging()
    ana_program()
