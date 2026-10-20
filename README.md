# Cổng tài khoản học viên FPT Aptech

Ứng dụng đăng ký, đăng nhập và quản trị tài khoản theo tutorial Spring Security 7 + Spring Boot 4.1, mở rộng bởi bài tập mục 11.

## Yêu cầu

- JDK 25
- Docker Desktop (MySQL 8.4 và Mailpit)
- Không cần cài Maven: project dùng Maven Wrapper

## Chạy

```bash
./mvnw spring-boot:run
```

Trên Windows PowerShell:

```powershell
./mvnw.cmd spring-boot:run
```

Ứng dụng: http://localhost:8080  
Hộp thư dev (Mailpit): http://localhost:8025

Tài khoản quản trị được tạo ở lần chạy đầu nếu hệ thống chưa có admin:

- Email: `admin@fptaptech.edu.vn`
- Mật khẩu: `Portal#Secure2026!`

Đăng nhập xong, tài khoản này bị đưa vào trang bật xác thực hai bước. Hãy đổi mật khẩu và đặt `APP_ADMIN_PASSWORD` trước khi dùng thật.

## Kiểm thử

```bash
./mvnw test
```

Test dùng H2, không cần Docker.

## Production

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=prod
```

Bắt buộc có các biến môi trường: `APP_BASE_URL`, `APP_ENCRYPTION_KEY` (32 byte, hex 64 ký tự hoặc Base64), `APP_REMEMBER_ME_KEY`, `APP_ADMIN_EMAIL`, `APP_ADMIN_PASSWORD`. Profile `prod` bật cookie `Secure` và HSTS.

## Chức năng

| Mã | Nội dung |
| --- | --- |
| F1 | Đăng ký bằng email, tài khoản `PENDING`, gửi link xác minh |
| F2 | Token một lần, hết hạn 24 giờ, lưu SHA-256, gửi lại tối đa 3 lần/giờ |
| F3 | Quên mật khẩu, token 30 phút, phản hồi giống nhau, hủy mọi phiên |
| F4 | Mật khẩu ≥ 12 ký tự, không chứa email, không nằm trong 10.000 mật khẩu phổ biến, không trùng 5 mật khẩu gần nhất |
| F5 | Sai mật khẩu 5 lần/15 phút thì khóa 15 phút, thông báo không tiết lộ tài khoản |
| F6 | TOTP RFC 6238, QR, 10 mã khôi phục; giảng viên và quản trị bắt buộc bật |
| F7 | Ghi nhớ đăng nhập 14 ngày trong database, thu hồi khi đổi mật khẩu |
| F8 | Tối đa 2 phiên, trang thiết bị có thời điểm, IP, trình duyệt, đăng xuất từ xa |
| F9 | Đổi mật khẩu phải nhập mật khẩu hiện tại, giữ phiên hiện tại, hủy phiên khác |
| F10 | Quản trị tìm/lọc, khóa, gán vai trò, buộc đăng xuất; luôn còn ít nhất một admin |
| F11 | Nhật ký đăng nhập, đăng xuất, khóa, mật khẩu, vai trò, bật/tắt 2FA |

Mô hình mối đe dọa: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
