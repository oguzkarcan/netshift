# netshift

Cut a device's **internet** while leaving its **Wi-Fi** connected — from the terminal.

```
  netshift · block · wlan0 192.168.1.20/24 · gw 192.168.1.1
   [ ] 192.168.1.31  3c:22:fb:aa:bb:cc  Apple          iPhone       açık
 > [x] 192.168.1.42  9c:5c:8e:11:22:33  Samsung        tablet-TV    KESİK 03:41

 6 cihaz · 1 kesik · 1 seçili | boşluk: seç  b: kes  r: geri aç  s: yenile  q: çık
```

No deauth, no router login, no app on the target device. The device keeps its Wi-Fi
association and simply cannot reach the internet.

> **Yetkili kullanım.** Bu araç yalnızca sahibi olduğunuz veya yazılı izniniz olan
> ağlarda, kendi cihazlarınızda kullanılmak üzere yazıldı. Başkasının ağında, haberi
> olmayan cihazlara uygulamak yetkisiz ağ müdahalesidir (bir tür hizmet engelleme) ve
> birçok ülkede suçtur. Ders/lab demolarında kendi telefonunuzu, kendi tabletinizi
> hedefleyin.

## Nasıl çalışıyor

Bir cihaz internete çıkarken önce "gateway'in MAC'i ne?" diye ARP ile sorar. `netshift`
o cihaza gateway'in MAC'i yerine **ağda var olmayan** bir MAC adresi (`02:00:00:00:00:01`)
bildirir. Cihazın paketleri yerel ağda ölür:

```
   telefon  ──"gateway = 02:00:...:01"──►  (kimse cevap vermez)   ✗ internet
      │
      └── Wi-Fi association: bozulmaz, sinyal tam, IP aynı
```

Bu yüzden cihazın Wi-Fi'ı düşmez, "bağlı ama internet yok" durumuna geçer — tam olarak
istenen davranış. Trafik sizin makinenizden **geçmez** (`block` modu), yani MITM
pozisyonuna girmezsiniz ve `ip_forward` açmanız gerekmez.

`mitm` modu ise eğitim amaçlı ikinci perde: her iki tarafa da zehirleme yapar,
`ip_forward`'ı açar ve trafiği gerçekten bu makineden geçirir — "ARP spoofing neden
tehlikeli" demosunda paketlerin akmaya devam ettiğini göstermek için.

## Kurulum

Linux (Arch/Omarchy):

```bash
sudo pacman -S python-scapy          # veya aşağıdaki venv yolu
```

macOS:

```bash
brew install python3
```

Her iki platformda, depo içinde:

```bash
./run.sh              # ilk çalıştırmada .venv kurar ve scapy indirir
sudo ./run.sh scan
```

Kalıcı kurulum isterseniz:

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
sudo .venv/bin/netshift scan
```

`scapy` root ister (ham soket). `sudo` ile çalıştırmak zorunlu; `run.sh` bunu sizin
için yapmaz, komutun başına `sudo` yazın.

## Hızlı başlangıç

```bash
sudo ./run.sh scan                 # ağdaki cihazlar: IP, MAC, üretici, hostname
sudo ./run.sh tui                  # etkileşimli liste
sudo ./run.sh block 192.168.1.42 --duration 5m
sudo ./run.sh mitm 192.168.1.42    # trafik bu makineden geçsin (demo)
sudo ./run.sh heal                 # çökme sonrası ARP kayıtlarını onar
```

TUI tuşları:

| Tuş | İşlev |
| --- | --- |
| `↑`/`↓` veya `k`/`j` | gezin |
| `boşluk` | seç / seçimi kaldır |
| `b` | seçili cihazların internetini kes |
| `r` | hepsini geri aç |
| `s` | yeniden tara (15 sn'de bir otomatik) |
| `q` | çık (çıkarken her şeyi geri alır) |

Üretici adları için bir kez:

```bash
sudo ./run.sh oui-update           # IEEE OUI listesini ~/.cache/netshift/oui.csv içine indirir
```

## Komutlar

```
netshift scan   [--iface X] [--gateway IP] [--no-names]
netshift tui    [--mode block|mitm]
netshift block  <IP...> [--mac MAC...] [--duration 15m] [--yes]
netshift mitm   <IP...> [--mac MAC...] [--duration 15m]
netshift heal
netshift oui-update
```

`--duration` bitince ARP kayıtları otomatik geri yüklenir. `Ctrl+C`, `SIGTERM` ve normal
çıkış da aynı temizliği yapar; `kill -9` durumunda `netshift heal`.

## Derste 5 dakikalık demo

1. `sudo ./run.sh tui` — cihaz listesi gelsin.
2. Kendi telefonunuzu seçin (`boşluk`), sonra `b`.
3. Telefonda: Wi-Fi simgesi **hâlâ dolu**, ama tarayıcıda sayfa açılmıyor. Uçak moduna
   alıp geri açın: Wi-Fi yine bağlanır, internet yine yok. Fark burada görünür.
4. `nft list ruleset` / router'da hiçbir kural yok, cihaza hiçbir şey kurulmadı — saldırı
   tamamen L2'de, ARP protokolünün "kimlik doğrulaması yok" varsayımı üzerinden.
5. `r` ile geri açın; telefon saniyeler içinde internete döner.
6. İkinci perde: `sudo ./run.sh mitm <cihaz>` + `sudo tcpdump -i <iface> -n host <cihaz>`
   ile düz HTTP/DNS trafiğinin okunabildiğini gösterin (HTTPS içeriği şifreli kalır, ama
   hedef adresler ve DNS görünür).
7. Kapanış: çözüm HTTPS değil, **ARP doğrulaması** — port güvenliği (Dynamic ARP
   Inspection), statik ARP, 802.1X, ayrık VLAN'lar.

## Sınırlar (dürüst liste)

- **IPv6**: araç IPv4 ARP üzerinde çalışır. Ağda IPv6 varsa cihaz IPv6 ile internete
  çıkmaya devam edebilir; o durumda `block` beklendiği gibi kesmez. IPv6 kapatın veya
  RA/NDP tarafını ayrıca ele alın.
- **İstemci izolasyonu açık ağlarda** (kafe/kurumsal guest Wi-Fi) cihazlar birbirinin
  L2 trafiğini göremez; bu araç orada çalışmaz — zaten çalışmaması da doğrusu.
- **Statik ARP** girişi olan cihazlar zehirlemeyi yok sayar.
- Cihaz Wi-Fi'dan düşerse, uykuya girerse veya MAC değiştirirse liste güncellenmeli.
- Aynı VLAN'daki yönetilen switch'lerde **Dynamic ARP Inspection** varsa zehirleme
  engellenir (kurumsal ağlarda tipik).
- `block` modu cihazın **yeni** bağlantılarını keser; mevcut TCP oturumları ARP önbelleği
  tazelenene kadar birkaç saniye daha paket gönderebilir.

## Neden router'dan yapmıyorsunuz?

Kendi ağınızın yöneticisiyseniz doğru yol router'dır: tek bir `nft`/MAC kuralı, siz
orada değilken de çalışır ve denetlenebilir. `netshift` bilerek router'a dokunmaz;
amacı **protokolün kendisini** göstermek — ARP'nin neden doğrulama gerektirdiğini
anlatmanın en kısa yolu.

## Lisans

MIT.
