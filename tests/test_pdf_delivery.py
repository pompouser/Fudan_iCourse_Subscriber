import email
import unittest
from unittest.mock import patch
from src.api.emailer import Emailer


class PDFDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.sender = Emailer()
        self.sender.sender = 'sender@example.com'
        self.sender.password = 'test-only'
        self.sender.receiver = 'receiver@example.com'
        self.items = [dict(course_title='材料结构', sub_title='第一讲',
                           date='2026-10-01', summary='中文笔记')]

    @patch('src.api.emailer.smtplib.SMTP_SSL')
    @patch('src.api.pdf_export.render_course_pdf', return_value=b'%PDF-test')
    def test_pdf_mime_and_chinese_filename(self, render, smtp):
        self.assertTrue(self.sender.send(self.items))
        message = email.message_from_string(smtp.return_value.__enter__.return_value
                                           .sendmail.call_args.args[2])
        self.assertEqual(message.get_content_type(), 'multipart/mixed')
        attachment = message.get_payload()[1]
        self.assertEqual(attachment.get_content_type(), 'application/pdf')
        self.assertEqual(attachment.get_payload(decode=True), b'%PDF-test')
        self.assertEqual(attachment.get_filename(), '01_材料结构.pdf')
        smtp.assert_called_once_with(self.sender.host, self.sender.port, timeout=60)

    @patch('src.api.emailer.smtplib.SMTP_SSL')
    @patch('src.api.pdf_export.render_course_pdf', side_effect=RuntimeError('render'))
    def test_render_failure_never_sends(self, render, smtp):
        with self.assertRaises(RuntimeError):
            self.sender.send(self.items)
        smtp.assert_not_called()

    @patch('src.api.emailer.time.sleep')
    @patch('src.api.emailer.smtplib.SMTP_SSL', side_effect=OSError('offline'))
    @patch('src.api.pdf_export.render_course_pdf', return_value=b'%PDF-test')
    def test_failed_delivery_returns_false(self, render, smtp, sleep):
        self.assertFalse(self.sender.send(self.items))
        self.assertEqual(smtp.call_count, 3)
        render.assert_called_once()

    def test_empty_does_not_render_or_connect(self):
        with patch('src.api.emailer.smtplib.SMTP_SSL') as smtp:
            self.assertTrue(self.sender.send([]))
            smtp.assert_not_called()
