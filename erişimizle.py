import logging

# Log dosyasının yeri ve adı
log_file = 'ip_log.txt'

# Loglama ayarlarının yapılandırılması
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

# Erişim izleme fonksiyonu
def log_ip_access(ip_address, accessed_url):
    log_message = f"IP: {ip_address} accessed URL: {accessed_url}"
    logging.info(log_message)

# Kullanıcı izni ile IP izleme ve loglama
user_ip = input("Please enter the user's IP address: ")
accessed_url = input("Please enter the accessed URL: ")

log_ip_access(user_ip, accessed_url)
