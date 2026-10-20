# Mô hình mối đe dọa

Hệ thống là cổng tài khoản học viên, giảng viên và quản trị viên. Kẻ tấn công có thể là người chưa có tài khoản, học viên, hoặc người chiếm cookie/phiên. Mục tiêu cần bảo vệ là mật khẩu, bí mật TOTP, token email, phiên đăng nhập và quyền quản trị.

## Tài khoản và mật khẩu

**Dò mật khẩu và nhồi thông tin đăng nhập.** Đăng nhập sai 5 lần trong 15 phút thì tài khoản bị khóa 15 phút. BCrypt làm mỗi lần thử đủ chậm. Thông báo luôn là “Sai email hoặc mật khẩu”, kể cả khi tài khoản không tồn tại, đang chờ xác minh, bị vô hiệu hóa hoặc đang khóa.

**Dò email theo thời gian phản hồi.** Username không tồn tại và mật khẩu sai đều đi qua một lần băm BCrypt và cùng số lần ghi nhận thất bại. Chênh lệch thời gian phản hồi của `POST /login` được giữ không quá 50 ms.

**Mật khẩu yếu hoặc tái sử dụng.** Mật khẩu mới phải dài 12–64 ký tự, không chứa email, không trùng danh sách 10.000 mật khẩu phổ biến và không trùng mật khẩu hiện tại cùng 5 mật khẩu gần nhất. Mật khẩu lưu bằng `DelegatingPasswordEncoder`. Tài khoản cũ dùng thuật toán yếu được băm lại bằng BCrypt khi đăng nhập đúng.

**Quên mật khẩu bị lợi dụng để dò email.** Yêu cầu đặt lại mật khẩu luôn trả cùng một trang, dù email có tồn tại hay không. Token hết hạn sau 30 phút, chỉ dùng một lần, và chỉ lưu SHA-256. Đặt lại xong thì mọi phiên và token ghi nhớ đăng nhập bị hủy. Mỗi IP chỉ được 20 yêu cầu mỗi giờ. Đăng ký cũng bị giới hạn 10 lần mỗi giờ theo IP; gửi lại email xác minh tối đa 3 lần mỗi giờ cho mỗi tài khoản.

## Phiên, cookie và trình duyệt

**Session fixation.** Sau khi đăng nhập, ứng dụng đổi session id. Cookie phiên là HttpOnly và SameSite=Lax; trên production còn có Secure và HSTS.

**Chiếm cookie ghi nhớ đăng nhập.** Remember-me lưu chuỗi token trong database, hiệu lực 14 ngày, cookie HttpOnly. Đổi mật khẩu, đặt lại mật khẩu, vô hiệu hóa tài khoản hoặc buộc đăng xuất đều xóa token. Nếu tài khoản đã bật TOTP, cookie này chỉ đưa người dùng tới bước nhập mã, không bỏ qua yếu tố thứ hai.

**Đăng nhập quá nhiều nơi.** Mỗi tài khoản giữ tối đa 2 phiên. Phiên cũ nhất kết thúc khi có phiên thứ ba. Trang thiết bị chỉ liệt kê phiên của chính chủ và chỉ cho hủy những phiên đó.

**CSRF.** Mọi form thay đổi dữ liệu dùng token CSRF do Thymeleaf gắn vào. Đăng xuất là POST.

**XSS và clickjacking.** Thymeleaf escape nội dung. CSP không cho script lạ hay style inline; ảnh QR dùng data URI. `frame-ancestors 'none'` và Referrer-Policy `no-referrer` giảm rò link chứa token qua Referer.

## Xác thực hai bước và bí mật

**Lấy bí mật TOTP từ database.** Secret được mã hóa AES-GCM trước khi ghi. Khóa 32 byte lấy từ `APP_ENCRYPTION_KEY`. Mã khôi phục chỉ lưu SHA-256, mỗi mã dùng một lần. Mã TOTP sai nhiều lần đi vào cùng cơ chế khóa tạm.

**Bỏ qua 2FA.** Giảng viên và quản trị chưa bật TOTP bị chặn ở trang thiết lập. Học viên được tắt 2FA chỉ khi nhập đúng mật khẩu hiện tại và mã đang hiệu lực. Quản trị có thể tắt 2FA của người khác; hành động này ghi nhật ký.

## Quyền quản trị

**Tự nâng quyền hoặc xóa admin cuối.** Học viên không mở được khu giảng viên và quản trị. Chỉ admin mời được giảng viên và admin. Hệ thống từ chối vô hiệu hóa, xóa hoặc gỡ vai trò nếu đó là admin đang hoạt động cuối cùng. Admin cũng không tự gỡ quyền admin của mình khi vẫn còn admin khác.

**Sửa phiên hoặc hồ sơ của người khác.** Đổi hồ sơ và mật khẩu lấy id từ phiên, không lấy từ form. Hủy phiên kiểm tra session thuộc đúng email đang đăng nhập.

## Nhật ký và rò rỉ dữ liệu

Nhật ký ghi đăng nhập thành công/thất bại, đăng xuất, khóa/mở, đổi mật khẩu, đổi vai trò và bật/tắt 2FA, kèm thời điểm, tài khoản, IP và user-agent. Mật khẩu, token và mã TOTP không được đưa vào nhật ký hay log ứng dụng. Hibernate không ghi bind parameter. Trang lỗi không trả stack trace.

IP lấy từ địa chỉ kết nối, không tin `X-Forwarded-For`, để tránh giả mạo địa chỉ khi chưa đứng sau proxy đã được cấu hình.
