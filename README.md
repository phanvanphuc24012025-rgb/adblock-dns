# adblock-dns

Một DNS server nhỏ chạy trên máy Windows của bạn để chặn quảng cáo/tracker
cho **cả mạng nhà**. Khi máy bật, các thiết bị dùng nó làm DNS sẽ bị lọc
quảng cáo. Khi máy tắt, router sẽ tự chuyển các thiết bị sang DNS công cộng
(1.1.1.1 / 8.8.8.8) nên mạng vẫn dùng bình thường, chỉ là không chặn ads nữa.

## 1. Cài đặt

Yêu cầu: đã cài [Node.js](https://nodejs.org) (bản LTS) trên Windows.

```
npm install
npm run update-all
```

`update-all` tải mọi danh mục chặn (quảng cáo, mã độc, cờ bạc, 18+, mạng xã
hội) về `data/lists/`. Từ bản 2.0, server tự tải các danh sách còn thiếu ở lần
chạy đầu, nên bước này không bắt buộc.

Nên chạy lại định kỳ (vài ngày/lần với malware list vì cập nhật liên tục,
vài tuần/lần với ad list) — có thể đặt thêm một Task Scheduler task riêng để
tự chạy `npm run update-all` hằng ngày.

## 2. Chạy thử

DNS chuẩn dùng port 53, cần quyền Administrator để mở port này trên Windows.

Mở **PowerShell as Administrator**, rồi:

```
cd đường-dẫn-tới-thư-mục-này
npm start
```

Nếu thấy dòng `DNS ad-blocker listening on 0.0.0.0:53` là server đã chạy.
Test nhanh bằng máy khác hoặc chính máy này:

```
nslookup doubleclick.net 127.0.0.1
```

Nếu trả về `0.0.0.0` → đã chặn thành công.

## 3. Đặt IP tĩnh cho máy Windows

Router cần biết chính xác địa chỉ máy bạn để trỏ DNS tới đó, nên đặt IP tĩnh
(hoặc DHCP reservation trong router — cách này tốt hơn vì không cần đổi cấu
hình trên Windows).

- **Cách A (khuyên dùng): DHCP reservation trên router** — vào trang quản trị
  router, tìm mục DHCP Reservation/Static Lease, gán một IP cố định (ví dụ
  `192.168.1.100`) cho địa chỉ MAC của máy Windows.
- **Cách B: đặt IP tĩnh thủ công trên Windows** — Settings → Network →
  đổi từ "Automatic (DHCP)" sang "Manual", nhập IP, subnet mask, gateway
  giống như bạn đang có nhưng cố định.

## 4. Trỏ DNS của mạng về máy này

Vào trang quản trị router (thường là `192.168.1.1` hoặc `192.168.0.1`), tìm
mục cấu hình DHCP/DNS, đặt:

- **Primary DNS**: IP tĩnh của máy Windows (vd `192.168.1.100`)
- **Secondary DNS**: `1.1.1.1` hoặc `8.8.8.8`

Các thiết bị sẽ ưu tiên hỏi máy bạn trước; nếu máy tắt/không phản hồi, chúng
tự động dùng DNS dự phòng sau vài giây timeout.

*Lưu ý:* một số router không cho đổi DNS qua DHCP, hoặc thiết bị cache DNS cũ
— có thể cần restart router/thiết bị sau khi đổi.

## 5. Mở Windows Firewall cho port 53

Chạy trong PowerShell as Administrator:

```
New-NetFirewallRule -DisplayName "DNS AdBlock UDP 53" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "DNS AdBlock TCP 53" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "DNS AdBlock Dashboard" -Direction Inbound -Protocol TCP -LocalPort 8053 -Action Allow
```

## 6. Tự khởi động khi bật máy (không cần đăng nhập)

Dùng Task Scheduler:

1. Mở **Task Scheduler** → Create Task (không phải Create Basic Task).
2. Tab **General**: đặt tên, chọn "Run whether user is logged on or not",
   tick "Run with highest privileges".
3. Tab **Triggers**: New → "At startup".
4. Tab **Actions**: New → Program/script: `node.exe` (đường dẫn đầy đủ, vd
   `C:\Program Files\nodejs\node.exe`), Add arguments: `index.js`,
   Start in: đường dẫn tới thư mục dự án này.
5. Lưu lại (sẽ hỏi mật khẩu tài khoản Windows để chạy nền được).

Máy khởi động lại → server tự chạy, không cần mở PowerShell thủ công nữa.

## Phát hiện mã độc (nâng cấp mới)

Ngoài chặn quảng cáo, server giờ có thêm 3 lớp bảo vệ:

1. **Chặn domain mã độc/phishing đã biết** — đối chiếu với danh mục "Mã độc / phishing"
   (nguồn URLhaus; nếu abuse.ch báo 401/403 khi tải, tạo Auth-Key miễn phí tại
   https://auth.abuse.ch/ rồi đặt biến môi trường `ABUSECH_AUTH_KEY`). Khi chặn, ghi log vào `security-alerts.log` kèm domain
   và IP thiết bị đã truy vấn — hữu ích để biết máy nào trong nhà đang dính
   phần mềm độc hại cố gọi về domain đó.
2. **Phát hiện DGA (Domain Generation Algorithm)** — nhiều mã độc/botnet tự
   sinh hàng loạt domain ngẫu nhiên (vd `xqzvpqoweiur.net`) để liên lạc với
   máy chủ điều khiển, né được blocklist tĩnh. `dga-detector.js` tính độ
   "ngẫu nhiên" của tên miền (entropy, tỷ lệ chữ số, chuỗi phụ âm dài...) để
   gắn cờ nghi vấn. Mặc định chỉ **ghi log cảnh báo**, không tự chặn (tránh
   chặn nhầm domain hợp lệ nhưng tên ngẫu nhiên như CDN, cloud storage). Muốn
   tự động chặn luôn, đặt `blockSuspectedDga` thành `true` trong `data/config.json`.
3. **Phát hiện "beaconing"** — nếu một thiết bị tra cứu **thất bại** (NXDOMAIN/lỗi)
   từ 20 domain khác nhau trở lên trong chưa tới 1 phút, đây là dấu hiệu điển
   hình của mã độc/DGA đang dò máy chủ điều khiển. (Bản cũ đếm mọi truy vấn nên
   báo nhầm khi mở một trang web nhiều domain.) Được ghi vào
   `security-alerts.log` kèm IP thiết bị; cùng một cảnh báo không lặp lại trong
   10 phút.

Nên thỉnh thoảng mở `security-alerts.log` để xem có cảnh báo bất thường
không — nếu thấy một thiết bị liên tục xuất hiện, đáng để kiểm tra máy đó.

## Dashboard quản lý (bản 2.0)

Mở `http://<IP-máy-bạn>:8053` trên bất kỳ thiết bị nào trong mạng nhà.

- **Xem** thống kê: mở tự do trong mạng nhà (đặt `DASHBOARD_PASSWORD` nếu muốn
  khóa cả phần xem).
- **Chỉnh sửa** luôn cần mật khẩu (user `admin`, đổi bằng `DASHBOARD_USER`).
  Lần chạy đầu server tạo mật khẩu ngẫu nhiên, in ra console và lưu ở
  `data/dashboard-password.txt`. Muốn tự đặt: biến môi trường `DASHBOARD_PASSWORD`.
- Mọi cấu hình lưu ở `data/config.json` (có thể sửa tay khi server đang tắt).
- Đừng mở port 8053 ra internet.

Các tab:

1. **Tổng quan** — thống kê hôm nay, biểu đồ 7 ngày (lưu qua các lần khởi động
   lại), top domain bị chặn (bấm *Cho phép* để mở chặn ngay), thống kê theo
   thiết bị, hoạt động gần đây.
2. **Danh mục** — bật/tắt từng nhóm (quảng cáo, mã độc, cờ bạc, 18+, mạng xã
   hội), thêm/xóa nguồn danh sách (hosts, danh sách domain, hoặc định dạng
   adblock `||domain^` như Hagezi/OISD), thêm domain thủ công, tạo danh mục riêng
   (vd `games`), nút cập nhật danh sách ngay.
3. **Cho phép / Chặn** — whitelist (ghi đè mọi thứ) và blacklist (chặn cho tất cả).
4. **Thiết bị & lịch** — đặt tên thiết bị theo IP, chặn thêm hoặc miễn trừ
   danh mục cho từng thiết bị, và lịch theo ngày/giờ (hỗ trợ qua đêm, vd
   22:00–06:00). Ví dụ: máy của con bị chặn mạng xã hội + cờ bạc mỗi đêm, máy
   bố mẹ miễn trừ 18+. Nên đặt IP cố định (DHCP reservation) cho các thiết bị này.
   Giờ tính theo đồng hồ máy chạy server.
5. **Thông báo** — Telegram / Discord khi có domain mã độc bị chặn, beaconing
   hoặc domain nghi vấn DGA.

**Tạm tắt chặn**: nút ở đầu trang tắt chặn 10/30/60 phút rồi tự bật lại.
Danh mục "thiết yếu" (mã độc, DoH) vẫn chặn trong lúc tạm tắt và không miễn
trừ được. Trạng thái tạm tắt nằm trong bộ nhớ nên khởi động lại server là bật lại chặn.

## Thông báo Telegram / Discord

- **Telegram**: tạo bot qua @BotFather lấy token; lấy chat id của bạn (vd qua
  @userinfobot), nhắn bot một tin trước. Nhập vào tab *Thông báo*, bấm *Gửi tin thử*.
- **Discord**: Server Settings → Integrations → Webhooks → copy URL.
- Mỗi cảnh báo giống nhau không lặp lại trong 10 phút, tối đa 10 tin/phút.

## Chặn DNS-over-HTTPS / né lọc

`doh-blocklist.txt` là danh mục "DNS-over-HTTPS" (luôn chặn): chặn các endpoint
DoH phổ biến để trình duyệt quay về DNS thường. Thêm nhà cung cấp mới bằng cách
mở file và thêm domain, mỗi dòng một domain.

## DNS-over-TLS / DNS-over-HTTPS cho điện thoại ngoài nhà (tùy chọn)

Server luôn nhận UDP + TCP port 53. Nếu có chứng chỉ TLS hợp lệ, server mở thêm:

- **DoT** port 853 (Android "Private DNS" dùng được),
- **DoH** `https://<tên-miền-của-bạn>:8443/dns-query`.

Điều kiện: một tên miền trỏ về IP nhà bạn (DDNS) + chứng chỉ tin cậy (vd Let's
Encrypt), đặt thành `data/certs/cert.pem` và `data/certs/key.pem`, mở/forward port
tương ứng trên router và Windows Firewall rồi khởi động lại. Không có file
chứng chỉ thì hai cổng này không bật. Lưu ý: mở DNS ra internet có rủi ro bị lợi dụng
(khuếch đại tấn công); chỉ làm khi hiểu rõ, và ưu tiên VPN về nhà (WireGuard/Tailscale)
nếu có thể.

## Tự động cập nhật danh sách

Server tự cập nhật mọi danh mục mỗi 24 giờ (đổi bằng `autoUpdateHours` trong
`data/config.json`, `0` để tắt). Danh sách tải lỗi hoặc quá nhỏ sẽ không ghi đè danh
sách cũ. Nguồn URLhaus (abuse.ch) có thể cần Auth-Key miễn phí
(https://auth.abuse.ch/) đặt vào biến môi trường `ABUSECH_AUTH_KEY`.

## Chạy như Windows Service (mới, khuyên dùng thay Task Scheduler)

Cách này ổn định hơn Task Scheduler: Windows tự khởi động lại service nếu
nó crash, và chạy được trước khi có ai đăng nhập vào máy.

```
npm install
npm run install-service
```

(chạy trong PowerShell as Administrator). Service tên `AdblockDNS` sẽ tự
khởi động cùng Windows từ giờ trở đi — không cần cấu hình Task Scheduler ở
Bước 6 nữa.

Muốn gỡ:
```
npm run uninstall-service
```

Xem trạng thái/log của service: mở **Services** (services.msc) trong
Windows, tìm "AdblockDNS".

## Tùy chỉnh

- **Bỏ chặn một domain**: dùng dashboard (tab *Cho phép / Chặn*). File
  `whitelist.txt` cũ vẫn được đọc nếu còn.
- **Đổi DNS thượng nguồn (upstream)**: sửa `upstream` trong `data/config.json`
  rồi khởi động lại server.
- **Chạy test**: `npm test` (không cần mạng).
- **Xem log**: khi server đang chạy trong cửa sổ console, mỗi truy vấn in ra
  `BLOCKED` hoặc `ALLOWED` kèm tên miền.

## Nâng cấp lên 2.0

- Danh sách chặn chuyển sang `data/lists/<danh-mục>.txt`; cấu hình sang
  `data/config.json`. File cũ `blocklist.txt`, `malwarelist.txt`, `adult-blocklist.txt`
  không còn dùng — có thể xóa. Server tự tải lại danh sách ở lần chạy đầu.
- `BLOCK_ADULT_CONTENT`, `BLOCK_SUSPECTED_DGA`... trong `index.js` đã chuyển thành
  cài đặt (tab *Danh mục*, hoặc `blockSuspectedDga` trong config).
- Từ bản 1.1: trả lời đúng loại truy vấn (AAAA chặn bằng `::`, HTTPS/SVCB rỗng),
  cache theo TTL, tải danh sách an toàn (timeout, không ghi đè bằng danh sách lỗi),
  beaconing chỉ đếm tra cứu thất bại.

## Giới hạn cần biết

- Chỉ lọc theo tên miền (DNS-level), không lọc được quảng cáo phục vụ qua
  domain dùng chung với nội dung chính (một số quảng cáo trong app/YouTube
  vẫn lọt qua).
- HTTPS/DoH (DNS over HTTPS) trên trình duyệt (Chrome/Firefox) có thể bỏ qua
  DNS này nếu bật "Secure DNS" — nên tắt tính năng đó trên các trình duyệt
  nếu muốn ad-blocker này có hiệu lực đầy đủ.
- Server này không mã hóa DNS traffic (dùng UDP thường), phù hợp cho mạng
  nhà tin cậy, không phải giải pháp bảo mật cao.
