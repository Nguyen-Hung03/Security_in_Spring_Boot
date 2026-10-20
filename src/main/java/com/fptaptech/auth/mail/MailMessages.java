package com.fptaptech.auth.mail;

public final class MailMessages {

    private MailMessages() {
    }

    public static String verify(String fullName, String link) {
        return """
                Xin chào %s,

                Mở liên kết sau để xác minh email. Liên kết có hiệu lực 24 giờ và chỉ dùng một lần:
                %s

                Nếu bạn không tạo tài khoản, hãy bỏ qua email này.
                """.formatted(fullName, link);
    }

    public static String reset(String link) {
        return """
                Có yêu cầu đặt lại mật khẩu cho tài khoản của bạn.
                Liên kết có hiệu lực 30 phút và chỉ dùng một lần:
                %s

                Nếu bạn không yêu cầu, hãy bỏ qua email này.
                """.formatted(link);
    }

    public static String invite(String fullName, String roleLabel, String link) {
        return """
                Xin chào %s,

                Bạn được mời tham gia cổng tài khoản FPT Aptech với vai trò %s.
                Mở liên kết sau để đặt mật khẩu. Liên kết có hiệu lực 24 giờ và chỉ dùng một lần:
                %s
                """.formatted(fullName, roleLabel, link);
    }
}
