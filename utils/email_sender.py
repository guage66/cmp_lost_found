import os
import smtplib
from email.header import Header
from email.mime.text import MIMEText
from email.utils import formataddr

from dotenv import load_dotenv


load_dotenv()


def send_email_code(to_email, code):
    mail_server = os.getenv("MAIL_SERVER", "").strip()
    mail_port = int(os.getenv("MAIL_PORT", "465").strip() or 465)
    mail_username = os.getenv("MAIL_USERNAME", "").strip()
    mail_password = os.getenv("MAIL_PASSWORD", "").strip()
    mail_sender = os.getenv("MAIL_SENDER", mail_username).strip()

    if not all([mail_server, mail_port, mail_username, mail_password, mail_sender]):
        return False, "\u90ae\u7bb1\u914d\u7f6e\u4e0d\u5b8c\u6574\uff0c\u8bf7\u68c0\u67e5 .env \u6587\u4ef6"

    subject = "校园综合服务平台｜注册邮箱验证码"

    content = f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <title>注册邮箱验证码</title>
    </head>
    <body style="margin:0; padding:0; background-color:#f4f6f8; font-family:Arial, 'Microsoft YaHei', sans-serif;">
        <div style="max-width:600px; margin:40px auto; background:#ffffff; border-radius:12px; overflow:hidden; box-shadow:0 4px 18px rgba(0,0,0,0.08);">
            <div style="background:linear-gradient(135deg, #2563eb, #1e40af); padding:24px 32px; color:#ffffff;">
                <h2 style="margin:0; font-size:22px; font-weight:600;">校园综合服务平台</h2>
                <p style="margin:8px 0 0; font-size:14px; opacity:0.9;">注册邮箱验证通知</p>
            </div>

            <div style="padding:32px;">
                <p style="font-size:16px; color:#333333; margin:0 0 18px;">您好！</p>

                <p style="font-size:15px; color:#555555; line-height:1.8; margin:0 0 24px;">
                    您正在进行校园综合服务平台账号注册。请在注册页面输入以下邮箱验证码，以完成邮箱验证。
                </p>

                <div style="text-align:center; margin:32px 0;">
                    <div style="display:inline-block; padding:16px 36px; background:#f1f5ff; border:1px solid #c7d2fe; border-radius:10px;">
                        <span style="display:block; font-size:13px; color:#64748b; margin-bottom:8px;">您的验证码</span>
                        <strong style="font-size:32px; letter-spacing:8px; color:#1d4ed8;">{code}</strong>
                    </div>
                </div>

                <p style="font-size:14px; color:#555555; line-height:1.8; margin:0 0 12px;">
                    该验证码将在 <strong style="color:#dc2626;">5 分钟</strong> 内有效，请尽快完成验证。
                </p>

                <p style="font-size:14px; color:#555555; line-height:1.8; margin:0 0 24px;">
                    为保障您的账号安全，请勿将验证码透露给他人。平台工作人员不会向您索要验证码。
               </p>

                <div style="background:#fff7ed; border-left:4px solid #f97316; padding:12px 16px; border-radius:6px;">
                    <p style="font-size:13px; color:#9a3412; line-height:1.6; margin:0;">
                        如果本次操作不是您本人发起，请忽略此邮件，无需进行任何处理。
                    </p>
                </div>
            </div>

         <div style="padding:18px 32px; background:#f8fafc; border-top:1px solid #e5e7eb;">
                <p style="margin:0; font-size:12px; color:#94a3b8; line-height:1.6;">
                    此邮件由系统自动发送，请勿直接回复。<br>
                    校园综合服务平台 · 账号安全中心
                </p>
            </div>
        </div>
    </body>
    </html>
    """

    message = MIMEText(content, "html", "utf-8")
    message["From"] = formataddr(("校园综合服务平台", mail_sender))
    message["To"] = formataddr(("用户", to_email))
    message["Subject"] = Header(subject, "utf-8")

    try:
        if mail_port == 465:
            with smtplib.SMTP_SSL(mail_server, mail_port) as smtp:
                smtp.login(mail_username, mail_password)
                result = smtp.sendmail(mail_sender, [to_email], message.as_string())
        else:
            with smtplib.SMTP(mail_server, mail_port) as smtp:
                smtp.starttls()
                smtp.login(mail_username, mail_password)
                result = smtp.sendmail(mail_sender, [to_email], message.as_string())

        print("sendmail result:", result)

        if result:
            return False, f"\u90ae\u4ef6\u670d\u52a1\u5668\u62d2\u6536\uff1a{result}"

        return True, "\u53d1\u9001\u6210\u529f"

    except smtplib.SMTPAuthenticationError as exc:
        return False, f"\u90ae\u7bb1\u767b\u5f55\u5931\u8d25\uff0c\u8bf7\u68c0\u67e5\u90ae\u7bb1\u8d26\u53f7\u6216\u5ba2\u6237\u7aef\u6388\u6743\u7801\uff1a{exc}"

    except smtplib.SMTPConnectError as exc:
        return False, f"\u8fde\u63a5 SMTP \u670d\u52a1\u5668\u5931\u8d25\uff0c\u8bf7\u68c0\u67e5\u670d\u52a1\u5668\u5730\u5740\u548c\u7aef\u53e3\uff1a{exc}"

    except smtplib.SMTPRecipientsRefused as exc:
        return False, f"\u6536\u4ef6\u90ae\u7bb1\u88ab\u62d2\u7edd\uff1a{exc.recipients}"

    except Exception as exc:
        return False, f"\u90ae\u4ef6\u53d1\u9001\u5f02\u5e38\uff1a{exc}"
