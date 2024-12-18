import pandas as pd
import numpy as np
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import scapy.all as scapy

# 1. Veri Setini Yükleme
print("NSL-KDD veri setini yükleme...")
data = pd.read_csv("KDDTrain+.txt", header=None)
data_test = pd.read_csv("KDDTest+.txt", header=None)

# Özellikler için sütun isimlendirme
columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
           'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 
           'num_compromised', 'root_shell', 'su_attempted', 'num_root', 
           'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 
           'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
           'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 
           'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 
           'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 
           'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
           'dst_host_serror_rate', 'dst_host_srv_serror_rate', 
           'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label']

# Veri setindeki sütun sayısını kontrol et
print(f"Eğitim veri setindeki sütun sayısı: {data.shape[1]}")
print(f"Test veri setindeki sütun sayısı: {data_test.shape[1]}")

# Eğer fazla sütun varsa son sütunu çıkar
if data.shape[1] == 43:
    data = data.iloc[:, :-1]
if data_test.shape[1] == 43:
    data_test = data_test.iloc[:, :-1]

# Sütun isimlerini ata
data.columns = columns
data_test.columns = columns

# Sadece sayısal sütunları kullan
features = ['src_bytes', 'dst_bytes', 'count', 'srv_count', 'dst_host_count', 'dst_host_srv_count']
data = data[features + ['label']]
data_test = data_test[features + ['label']]

# 2. Etiketleri Binarize Et
print("Etiketleri normal ve anormal olarak sınıflandırma...")
def label_binarize(label):
    return 0 if label == 'normal' else 1

data['label'] = data['label'].apply(label_binarize)
data_test['label'] = data_test['label'].apply(label_binarize)

# 3. Veriyi Normalize Et
print("Veriyi normalize etme...")
scaler = StandardScaler()

# Veriyi DataFrame'e dönüştürme
data_df = pd.DataFrame(data[features])
data_test_df = pd.DataFrame(data_test[features])

# Normalize edilmiş veriyi elde etme
data[features] = scaler.fit_transform(data_df)
data_test[features] = scaler.transform(data_test_df)

# 4. K-Means Modelini Eğit
print("K-Means modelini eğitme...")
kmeans = KMeans(n_clusters=2, random_state=42)
kmeans.fit(data[features])
data['cluster'] = kmeans.predict(data[features])
data_test['cluster'] = kmeans.predict(data_test[features])

# 5. Model Performansını Değerlendirme
print("Model performansını değerlendirme:")
print("Eğitim seti sonuçları:")
print(classification_report(data['label'], data['cluster'], target_names=['Normal', 'Anormal']))

print("Test seti sonuçları:")
print(classification_report(data_test['label'], data_test['cluster'], target_names=['Normal', 'Anormal']))

# 6. Gerçek Zamanlı Ağ Trafiği Dinleme
print("Gerçek zamanlı ağ trafiğini analiz etmek için kod...")

def analyze_packet(packet):
    print(f"Paketi analiz ediyorum: {packet.summary()}")  # Paket bilgilerini yazdır
    if packet.haslayer(scapy.IP):
        if packet.haslayer(scapy.Raw):
            src_bytes = len(packet[scapy.Raw].load)
        else:
            src_bytes = 0  # Eğer Raw katmanı yoksa, sıfır byte al
        dst_bytes = len(packet)

        # Özellikleri düzenleyin (sadece birkaç özellik için)
        features = np.array([src_bytes, dst_bytes, 0, 0, 0, 0]).reshape(1, -1)

        # Özellikleri DataFrame'e dönüştür
        features_df = pd.DataFrame(features, columns=['src_bytes', 'dst_bytes', 'count', 'srv_count', 'dst_host_count', 'dst_host_srv_count'])

        # Özellikleri normalize et
        scaled_features = scaler.transform(features_df)

        # KMeans ile tahmin yap
        cluster = kmeans.predict(scaled_features)[0]
        if cluster == 1:  # Anormal bir paket ise
            print(f"[ANOMALİ] Paket boyutu: {dst_bytes} (Kaynak: {packet[scapy.IP].src}, Hedef: {packet[scapy.IP].dst})")

# Trafiği dinlemek için aşağıdaki satırı açabilirsiniz:
scapy.sniff(prn=analyze_packet, store=False)
